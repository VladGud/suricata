
# Добавление нового протокола в suricata

## Автоматическая генерация шаблоного кода
```sh
./scripts/setup-app-layer.py --parser --logger BacNetIP
```

## Изменение шаблона

1. Добавление собственного парсера для протокола
1. Изменение шаблона декодера. Адаптируем код транзакций и состояний потоков под новый протокол. 
1. Добавление собственных event(различные негативные/позитивные события, которые можно отслеживать через правила) для протокола. 
1. Изменение транспортного протокола (**TCP/UDP**) и порта, на котором ожидается новый протокол.
1. Изменение шаблона логера `logger.rs`.

Пример парсера BacNet:
```rust
use nom7::{
    bytes::streaming::take,
    number::streaming::{be_u8, be_u16},
    IResult,
};

use std::fmt;

#[derive(PartialEq, Eq, Debug)]
pub struct BacNetPacket {
    pub bvlc_type: u8,
    pub bvlc_func: u8,
    pub length: u16,
    pub other_data: Vec<u8>,
}

impl fmt::Display for BacNetPacket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "BacNetPacket {{ bvlc_type: {}, bvlc_func: {}, length: {}, other_data: {:?} }}",
            self.bvlc_type, self.bvlc_func, self.length, self.other_data
        )
    }
}

pub fn parse_message(i: &[u8]) -> IResult<&[u8], BacNetPacket> {
    let (i, bvlc_type) = be_u8(i)?;
    let (i, bvlc_func) = be_u8(i)?;
    let (i, length) = be_u16(i)?;
    let (i, other_data) = take(i.len())(i)?;

    let packet = BacNetPacket {
        bvlc_type: bvlc_type,
        bvlc_func: bvlc_func,
        length: length,
        other_data: other_data.to_vec(),
    };

    Ok((i, packet))
}
```

Пример кода транзакций и состояний:
```rust
use super::parser;
use crate::applayer::{self, *};
use crate::core::{AppProto, Flow, ALPROTO_UNKNOWN, IPPROTO_UDP};
use nom7 as nom;
use std;
use std::collections::VecDeque;
use std::ffi::CString;
use std::os::raw::{c_char, c_int, c_void};

static mut ALPROTO_BACNETIP: AppProto = ALPROTO_UNKNOWN;

#[derive(Debug, AppLayerEvent)]
enum BacNetIPEvent {
    TransactionFound, 
}

pub struct BacNetIPTransaction {
    tx_id: u64,
    pub request: Option<parser::BacNetPacket>,
    pub response: Option<parser::BacNetPacket>,

    tx_data: AppLayerTxData,
}

impl Default for BacNetIPTransaction {
    fn default() -> Self {
        Self::new()
    }
}

impl BacNetIPTransaction {
    pub fn new() -> BacNetIPTransaction {
        Self {
            tx_id: 0,
            request: None,
            response: None,
            tx_data: AppLayerTxData::new(),
        }
    }

    fn set_event(&mut self, event: BacNetIPEvent) {
        self.tx_data.set_event(event as u8);
    }
}

impl Transaction for BacNetIPTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

#[derive(Default)]
pub struct BacNetIPState {
    state_data: AppLayerStateData,
    tx_id: u64,
    transactions: VecDeque<BacNetIPTransaction>,
}

impl State<BacNetIPTransaction> for BacNetIPState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&BacNetIPTransaction> {
        self.transactions.get(index)
    }
}

impl BacNetIPState {
    pub fn new() -> Self {
        Default::default()
    }

    // Free a transaction by ID.
    fn free_tx(&mut self, tx_id: u64) {
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &self.transactions[i];
            if tx.tx_id == tx_id + 1 {
                found = true;
                index = i;
                break;
            }
        }
        if found {
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&BacNetIPTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn new_tx(&mut self) -> BacNetIPTransaction {
        let mut tx = BacNetIPTransaction::new();
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        return tx;
    }

    fn find_request(&mut self) -> Option<&mut BacNetIPTransaction> {
        self.transactions.iter_mut().find(|tx| tx.response.is_none())
    }

    fn parse_request(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty requests.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        let mut start = input;
        while !start.is_empty() {
            match parser::parse_message(start) {
                Ok((rem, request)) => {
                    start = rem;

                    SCLogNotice!("Request: {}", request);
                    let mut tx = self.new_tx();
                    tx.request = Some(request);
                    self.transactions.push_back(tx);
                }
                Err(nom::Err::Incomplete(_)) => {
                    // Not enough data. This parser doesn't give us a good indication
                    // of how much data is missing so just ask for one more byte so the
                    // parse is called as soon as more data is received.
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
            }
        }

        // Input was fully consumed.
        return AppLayerResult::ok();
    }

    fn parse_response(&mut self, input: &[u8]) -> AppLayerResult {
        // We're not interested in empty responses.
        if input.is_empty() {
            return AppLayerResult::ok();
        }

        let mut start = input;
        while !start.is_empty() {
            match parser::parse_message(start) {
                Ok((rem, response)) => {
                    start = rem;

                    if let Some(tx) =  self.find_request() {
                        tx.response = Some(response);
                        SCLogNotice!("Found response for request:");
                        SCLogNotice!("- Request: {:?}", tx.request);
                        SCLogNotice!("- Response: {:?}", tx.response);
                        tx.set_event(BacNetIPEvent::TransactionFound);
                    }
                }
                Err(nom::Err::Incomplete(_)) => {
                    let consumed = input.len() - start.len();
                    let needed = start.len() + 1;
                    return AppLayerResult::incomplete(consumed as u32, needed as u32);
                }
                Err(_) => {
                    return AppLayerResult::err();
                }
            }
        }

        // All input was fully consumed.
        return AppLayerResult::ok();
    }
}

/// Probe for a valid header.
///
/// As this bacnetip protocol uses messages prefixed with the size
/// as a string followed by a ':', we look at up to the first 10
/// characters for that pattern.
fn probe(input: &[u8]) -> nom::IResult<&[u8], ()> {
    let (rem, _) = parser::parse_message(input)?;
    Ok((rem, ()))
}

// C exports.

/// C entry point for a probing parser.
unsafe extern "C" fn rs_bacnetip_probing_parser(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    // Need at least 3 bytes.
    if input_len > 3 && !input.is_null() {
        let slice = build_slice!(input, input_len as usize);
        if probe(slice).is_ok() {
            return ALPROTO_BACNETIP;
        }
    }
    return ALPROTO_UNKNOWN;
}

extern "C" fn rs_bacnetip_state_new(
    _orig_state: *mut c_void, _orig_proto: AppProto,
) -> *mut c_void {
    let state = BacNetIPState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut c_void;
}

unsafe extern "C" fn rs_bacnetip_state_free(state: *mut c_void) {
    std::mem::drop(Box::from_raw(state as *mut BacNetIPState));
}

unsafe extern "C" fn rs_bacnetip_state_tx_free(state: *mut c_void, tx_id: u64) {
    let state = cast_pointer!(state, BacNetIPState);
    state.free_tx(tx_id);
}

unsafe extern "C" fn rs_bacnetip_parse_request(
    _flow: *const Flow, state: *mut c_void, pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let eof = AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0;

    if eof {
        // If needed, handle EOF, or pass it into the parser.
        return AppLayerResult::ok();
    }

    let state = cast_pointer!(state, BacNetIPState);

    let buf = stream_slice.as_slice();
    state.parse_request(buf)

}

unsafe extern "C" fn rs_bacnetip_parse_response(
    _flow: *const Flow, state: *mut c_void, pstate: *mut c_void, stream_slice: StreamSlice,
    _data: *const c_void,
) -> AppLayerResult {
    let _eof = AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0;
    let state = cast_pointer!(state, BacNetIPState);

    let buf = stream_slice.as_slice();
    state.parse_response(buf)
}

unsafe extern "C" fn rs_bacnetip_state_get_tx(state: *mut c_void, tx_id: u64) -> *mut c_void {
    let state = cast_pointer!(state, BacNetIPState);
    match state.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

unsafe extern "C" fn rs_bacnetip_state_get_tx_count(state: *mut c_void) -> u64 {
    let state = cast_pointer!(state, BacNetIPState);
    return state.tx_id;
}

unsafe extern "C" fn rs_bacnetip_tx_get_alstate_progress(tx: *mut c_void, _direction: u8) -> c_int {
    let tx = cast_pointer!(tx, BacNetIPTransaction);

    // Transaction is done if we have a response.
    if tx.response.is_some() {
        return 1;
    }
    return 0;
}

export_tx_data_get!(rs_bacnetip_get_tx_data, BacNetIPTransaction);
export_state_data_get!(rs_bacnetip_get_state_data, BacNetIPState);

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"bacnetip\0";

#[no_mangle]
pub unsafe extern "C" fn rs_bacnetip_register_parser() {

    let default_port = CString::new("[47808]").unwrap();
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_UDP,
        probe_ts: Some(rs_bacnetip_probing_parser),
        probe_tc: Some(rs_bacnetip_probing_parser),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_bacnetip_state_new,
        state_free: rs_bacnetip_state_free,
        tx_free: rs_bacnetip_state_tx_free,
        parse_ts: rs_bacnetip_parse_request,
        parse_tc: rs_bacnetip_parse_response,
        get_tx_count: rs_bacnetip_state_get_tx_count,
        get_tx: rs_bacnetip_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_bacnetip_tx_get_alstate_progress,
        get_eventinfo: Some(BacNetIPEvent::get_event_info),
        get_eventinfo_byid: Some(BacNetIPEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(
            applayer::state_get_tx_iterator::<BacNetIPState, BacNetIPTransaction>,
        ),
        get_tx_data: rs_bacnetip_get_tx_data,
        get_state_data: rs_bacnetip_get_state_data,
        apply_tx_config: None,
        flags: 0,
        truncate: None,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
    };

    let ip_proto_str = CString::new("udp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_BACNETIP = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogNotice!("Rust bacnetip parser registered.");
    } else {
        SCLogNotice!("Protocol detector and parser disabled for BACNETIP.");
    }
}

```

# Добавление новых ключевых слов в suricata

## Генерация кода
```sh
./scripts/setup-app-layer.py --parser --logger BacNetIP
```
