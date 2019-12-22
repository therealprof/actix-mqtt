use super::{ConnectAckFlags, ConnectFlags, FixedHeader, WILL_QOS_SHIFT};
use crate::error::ParseError;
use crate::packet::property_type as pt;
use crate::packet::*;
use crate::proto::*;
use bytes::buf::ext::{BufExt, Take as BufTake};
use bytes::{Buf, Bytes};
use std::convert::{TryFrom, TryInto};
use std::io::Cursor;
use std::num::{NonZeroU16, NonZeroU32};

mod parse;
use parse::{Parse, Property};

type UserProperty = (ByteStr, ByteStr);

pub(crate) fn read_packet(mut src: Bytes, header: FixedHeader) -> Result<Packet, ParseError> {
    match header.first_byte {
        packet_type::PUBLISH_START..=packet_type::PUBLISH_END => {
            decode_publish_packet(src, header.first_byte & 0b0000_1111)
        }
        packet_type::PUBACK => Ok(Packet::PublishAck(decode_publish_ack(&mut src)?)),
        packet_type::CONNECT => decode_connect_packet(&mut src),
        packet_type::CONNACK => decode_connect_ack_packet(&mut src),
        packet_type::PUBREC => Ok(Packet::PublishReceived(decode_publish_ack(&mut src)?)),
        packet_type::PUBREL => Ok(Packet::PublishRelease(decode_publish_ack2(&mut src)?)),
        packet_type::PUBCOMP => Ok(Packet::PublishComplete(decode_publish_ack2(&mut src)?)),
        packet_type::SUBSCRIBE => decode_subscribe_packet(&mut src),
        packet_type::SUBACK => decode_subscribe_ack_packet(&mut src),
        packet_type::UNSUBSCRIBE => decode_unsubscribe_packet(&mut src),
        packet_type::UNSUBACK => decode_unsubscribe_ack_packet(&mut src),
        packet_type::PINGREQ => Ok(Packet::PingRequest),
        packet_type::PINGRESP => Ok(Packet::PingResponse),
        packet_type::DISCONNECT => decode_disconnect_packet(&mut src),
        packet_type::AUTH => decode_auth_packet(&mut src),
        _ => Err(ParseError::UnsupportedPacketType),
    }
}

macro_rules! check_flag {
    ($flags:expr, $flag:expr) => {
        ($flags & $flag.bits()) == $flag.bits()
    };
}

pub fn decode_variable_length(src: &[u8]) -> Result<Option<(u32, usize)>, ParseError> {
    let mut cur = Cursor::new(src);
    match decode_variable_length_cursor(&mut cur) {
        Ok(len) => Ok(Some((len, cur.position() as usize))),
        Err(ParseError::MalformedPacket) => Ok(None),
        Err(e) => Err(e),
    }
}

#[allow(clippy::cast_lossless)] // safe: allow cast through `as` because it is type-safe
fn decode_variable_length_cursor<B: Buf>(src: &mut B) -> Result<u32, ParseError> {
    let mut shift: u32 = 0;
    let mut len: u32 = 0;
    loop {
        ensure!(src.has_remaining(), ParseError::MalformedPacket);
        let val = src.get_u8();
        len += ((val & 0b0111_1111u8) as u32) << shift;
        if val & 0b1000_0000 == 0 {
            return Ok(len);
        } else {
            ensure!(shift < 21, ParseError::InvalidLength);
            shift += 7;
        }
    }
}

fn decode_connect_packet(src: &mut Bytes) -> Result<Packet, ParseError> {
    ensure!(src.remaining() >= 10, ParseError::InvalidLength);
    let len = src.get_u16();
    ensure!(
        len == 4 && &src.bytes()[0..4] == b"MQTT",
        ParseError::InvalidProtocol
    );
    src.advance(4);

    let level = src.get_u8();
    ensure!(
        level == DEFAULT_MQTT_LEVEL,
        ParseError::UnsupportedProtocolLevel
    );

    let flags = src.get_u8();
    ensure!(
        (flags & 0b0000_0001) == 0,
        ParseError::ConnectReservedFlagSet
    );

    let keep_alive = src.get_u16();

    // reading properties
    let mut session_expiry_interval_secs = None;
    let mut auth_method = None;
    let mut auth_data = None;
    let mut request_problem_info = None;
    let mut request_response_info = None;
    let mut receive_max = None;
    let mut topic_alias_max = None;
    let mut user_properties = Vec::new();
    let mut max_packet_size = None;
    let prop_src = &mut take_properties(src)?;
    while prop_src.has_remaining() {
        match prop_src.get_u8() {
            pt::SESS_EXPIRY_INT => session_expiry_interval_secs.read_value(prop_src)?,
            pt::AUTH_METHOD => auth_method.read_value(prop_src)?,
            pt::AUTH_DATA => auth_data.read_value(prop_src)?,
            pt::REQ_PROB_INFO => request_problem_info.read_value(prop_src)?,
            pt::REQ_RESP_INFO => request_response_info.read_value(prop_src)?,
            pt::RECEIVE_MAX => receive_max.read_value(prop_src)?,
            pt::TOPIC_ALIAS_MAX => topic_alias_max.read_value(prop_src)?,
            pt::USER => user_properties.push(UserProperty::parse(prop_src)?),
            pt::MAX_PACKET_SIZE => max_packet_size.read_value(prop_src)?,
            _ => return Err(ParseError::MalformedPacket),
        }
    }

    let client_id = ByteStr::parse(src)?;

    ensure!(
        // todo: [MQTT-3.1.3-8]?
        !client_id.is_empty() || check_flag!(flags, ConnectFlags::CLEAN_START),
        ParseError::InvalidClientId
    );

    let last_will = if check_flag!(flags, ConnectFlags::WILL) {
        Some(decode_last_will(src, flags)?)
    } else {
        None
    };

    let username = if check_flag!(flags, ConnectFlags::USERNAME) {
        Some(ByteStr::parse(src)?)
    } else {
        None
    };
    let password = if check_flag!(flags, ConnectFlags::PASSWORD) {
        Some(Bytes::parse(src)?)
    } else {
        None
    };

    Ok(Packet::Connect(Connect {
        protocol: Protocol::MQTT(level),
        clean_start: check_flag!(flags, ConnectFlags::CLEAN_START),
        keep_alive,

        session_expiry_interval_secs,
        auth_method,
        auth_data,
        request_problem_info,
        request_response_info,
        receive_max,
        topic_alias_max: topic_alias_max.unwrap_or(0u16),
        user_properties,
        max_packet_size,

        client_id,
        last_will,
        username,
        password,
    }))
}

fn decode_last_will(src: &mut Bytes, flags: u8) -> Result<LastWill, ParseError> {
    let mut will_delay_interval_sec = None;
    let mut correlation_data = None;
    let mut message_expiry_interval = None;
    let mut content_type = None;
    let mut user_properties = Vec::new();
    let mut is_utf8_payload = None;
    let mut response_topic = None;
    let prop_src = &mut take_properties(src)?;
    while prop_src.has_remaining() {
        match prop_src.get_u8() {
            pt::WILL_DELAY_INT => will_delay_interval_sec.read_value(prop_src)?,
            pt::CORR_DATA => correlation_data.read_value(prop_src)?,
            pt::MSG_EXPIRY_INT => message_expiry_interval.read_value(prop_src)?,
            pt::CONTENT_TYPE => content_type.read_value(prop_src)?,
            pt::UTF8_PAYLOAD => is_utf8_payload.read_value(prop_src)?,
            pt::RESP_TOPIC => response_topic.read_value(prop_src)?,
            pt::USER => user_properties.push(UserProperty::parse(prop_src)?),
            _ => return Err(ParseError::MalformedPacket),
        }
    }

    let topic = ByteStr::parse(src)?;
    let message = Bytes::parse(src)?;
    Ok(LastWill {
        qos: QoS::try_from((flags & ConnectFlags::WILL_QOS.bits()) >> WILL_QOS_SHIFT)?,
        retain: check_flag!(flags, ConnectFlags::WILL_RETAIN),
        topic,
        message,
        will_delay_interval_sec,
        correlation_data,
        message_expiry_interval,
        content_type,
        user_properties,
        is_utf8_payload,
        response_topic,
    })
}

fn decode_connect_ack_packet(src: &mut Bytes) -> Result<Packet, ParseError> {
    ensure!(src.remaining() >= 2, ParseError::InvalidLength);
    let flags = src.get_u8();
    ensure!(
        (flags & 0b1111_1110) == 0,
        ParseError::ConnAckReservedFlagSet
    );

    let reason_code = src.get_u8().try_into()?;

    let prop_src = &mut take_properties(src)?;

    let mut session_expiry_interval_secs = None;
    let mut receive_max = None;
    let mut max_qos = None;
    let mut retain_available = None;
    let mut max_packet_size = None;
    let mut assigned_client_id = None;
    let mut topic_alias_max = None;
    let mut reason_string = None;
    let mut user_properties = Vec::new();
    let mut wildcard_sub_avail = None;
    let mut sub_ids_avail = None;
    let mut shared_sub_avail = None;
    let mut server_ka_sec = None;
    let mut response_info = None;
    let mut server_reference = None;
    let mut auth_method = None;
    let mut auth_data = None;
    while prop_src.has_remaining() {
        match prop_src.get_u8() {
            pt::SESS_EXPIRY_INT => session_expiry_interval_secs.read_value(prop_src)?,
            pt::RECEIVE_MAX => receive_max.read_value(prop_src)?,
            pt::MAX_QOS => {
                ensure!(max_qos.is_none(), ParseError::MalformedPacket); // property is set twice while not allowed
                ensure!(prop_src.has_remaining(), ParseError::InvalidLength);
                max_qos = Some(prop_src.get_u8().try_into()?);
            }
            pt::RETAIN_AVAIL => retain_available.read_value(prop_src)?,
            pt::MAX_PACKET_SIZE => max_packet_size.read_value(prop_src)?,
            pt::ASSND_CLIENT_ID => assigned_client_id.read_value(prop_src)?,
            pt::TOPIC_ALIAS_MAX => topic_alias_max.read_value(prop_src)?,
            pt::REASON_STRING => reason_string.read_value(prop_src)?,
            pt::USER => user_properties.push(UserProperty::parse(prop_src)?),
            pt::WILDCARD_SUB_AVAIL => wildcard_sub_avail.read_value(prop_src)?,
            pt::SUB_IDS_AVAIL => sub_ids_avail.read_value(prop_src)?,
            pt::SHARED_SUB_AVAIL => shared_sub_avail.read_value(prop_src)?,
            pt::SERVER_KA => server_ka_sec.read_value(prop_src)?,
            pt::RESP_INFO => response_info.read_value(prop_src)?,
            pt::SERVER_REF => server_reference.read_value(prop_src)?,
            pt::AUTH_METHOD => auth_method.read_value(prop_src)?,
            pt::AUTH_DATA => auth_data.read_value(prop_src)?,
            _ => return Err(ParseError::MalformedPacket),
        }
    }
    ensure!(!src.has_remaining(), ParseError::InvalidLength);

    Ok(Packet::ConnectAck(ConnectAck {
        session_present: check_flag!(flags, ConnectAckFlags::SESSION_PRESENT),
        reason_code,
        session_expiry_interval_secs,
        receive_max,
        max_qos,
        retain_available,
        max_packet_size,
        assigned_client_id,
        topic_alias_max: topic_alias_max.unwrap_or(0u16),
        reason_string,
        user_properties,
        wildcard_subscription_available: wildcard_sub_avail,
        subscription_identifiers_available: sub_ids_avail,
        shared_subscription_available: shared_sub_avail,
        server_keepalive_sec: server_ka_sec,
        response_info,
        server_reference,
        auth_method,
        auth_data,
    }))
}

fn decode_disconnect_packet(src: &mut Bytes) -> Result<Packet, ParseError> {
    if src.has_remaining() {
        let reason_code = src.get_u8().try_into()?;

        let mut session_expiry_interval_secs = None;
        let mut server_reference = None;
        let mut reason_string = None;
        let mut user_properties = Vec::new();

        let prop_src = &mut take_properties(src)?;
        while prop_src.has_remaining() {
            match prop_src.get_u8() {
                pt::SESS_EXPIRY_INT => session_expiry_interval_secs.read_value(prop_src)?,
                pt::REASON_STRING => reason_string.read_value(prop_src)?,
                pt::USER => user_properties.push(UserProperty::parse(prop_src)?),
                pt::SERVER_REF => server_reference.read_value(prop_src)?,
                _ => return Err(ParseError::MalformedPacket),
            }
        }
        ensure!(!src.has_remaining(), ParseError::InvalidLength);

        Ok(Packet::Disconnect(Disconnect {
            reason_code,
            session_expiry_interval_secs,
            server_reference,
            reason_string,
            user_properties,
        }))
    } else {
        Ok(Packet::Disconnect(Disconnect {
            reason_code: DisconnectReasonCode::NormalDisconnection,
            session_expiry_interval_secs: None,
            server_reference: None,
            reason_string: None,
            user_properties: Vec::new(),
        }))
    }
}

fn decode_auth_packet(src: &mut Bytes) -> Result<Packet, ParseError> {
    if src.has_remaining() {
        ensure!(src.remaining() > 1, ParseError::InvalidLength);
        let reason_code = src.get_u8().try_into()?;

        let mut auth_method = None;
        let mut auth_data = None;
        let mut reason_string = None;
        let mut user_properties = Vec::new();

        if reason_code != AuthReasonCode::Success || src.has_remaining() {
            let prop_src = &mut take_properties(src)?;
            while prop_src.has_remaining() {
                match prop_src.get_u8() {
                    pt::AUTH_METHOD => auth_method.read_value(prop_src)?,
                    pt::AUTH_DATA => auth_data.read_value(prop_src)?,
                    pt::REASON_STRING => reason_string.read_value(prop_src)?,
                    pt::USER => user_properties.push(UserProperty::parse(prop_src)?),
                    _ => return Err(ParseError::MalformedPacket),
                }
            }
            ensure!(!src.has_remaining(), ParseError::InvalidLength);
        }

        Ok(Packet::Auth(Auth {
            reason_code,
            auth_method,
            auth_data,
            reason_string,
            user_properties,
        }))
    } else {
        Ok(Packet::Auth(Auth {
            reason_code: AuthReasonCode::Success,
            auth_method: None,
            auth_data: None,
            reason_string: None,
            user_properties: Vec::new(),
        }))
    }
}

fn decode_publish_packet(mut src: Bytes, packet_flags: u8) -> Result<Packet, ParseError> {
    let topic = ByteStr::parse(&mut src)?;
    let qos = QoS::try_from((packet_flags & 0b0110) >> 1)?;
    let packet_id = if qos == QoS::AtMostOnce {
        None
    } else {
        Some(NonZeroU16::parse(&mut src)?) // packet id = 0 encountered
    };

    let properties = parse_publish_properties(&mut src)?;
    let payload = src;

    Ok(Packet::Publish(Publish {
        dup: (packet_flags & 0b1000) == 0b1000,
        qos,
        retain: (packet_flags & 0b0001) == 0b0001,
        topic,
        packet_id,
        payload,
        properties,
    }))
}

fn parse_publish_properties(src: &mut Bytes) -> Result<PublishProperties, ParseError> {
    let prop_src = &mut take_properties(src)?;

    let mut message_expiry_interval = None;
    let mut topic_alias = None;
    let mut content_type = None;
    let mut correlation_data = None;
    let mut subscription_ids = None;
    let mut response_topic = None;
    let mut is_utf8_payload = None;
    let mut user_props = Vec::new();

    while prop_src.has_remaining() {
        match prop_src.get_u8() {
            pt::UTF8_PAYLOAD => is_utf8_payload.read_value(prop_src)?,
            pt::MSG_EXPIRY_INT => message_expiry_interval.read_value(prop_src)?,
            pt::CONTENT_TYPE => content_type.read_value(prop_src)?,
            pt::RESP_TOPIC => response_topic.read_value(prop_src)?,
            pt::CORR_DATA => correlation_data.read_value(prop_src)?,
            pt::SUB_ID => {
                let id = decode_variable_length_cursor(prop_src)?;
                subscription_ids
                    .get_or_insert_with(Vec::new)
                    .push(NonZeroU32::new(id).ok_or(ParseError::MalformedPacket)?);
            }
            pt::TOPIC_ALIAS => topic_alias.read_value(prop_src)?,
            pt::USER => user_props.push(<(ByteStr, ByteStr)>::parse(prop_src)?),
            _ => return Err(ParseError::MalformedPacket),
        }
    }

    Ok(PublishProperties {
        message_expiry_interval,
        topic_alias,
        content_type,
        correlation_data,
        subscription_ids,
        response_topic,
        is_utf8_payload,
        user_properties: user_props,
    })
}

fn decode_publish_ack(src: &mut Bytes) -> Result<PublishAck, ParseError> {
    let packet_id = NonZeroU16::parse(src)?;
    let (reason_code, properties) = if src.has_remaining() {
        let reason_code = src.get_u8().try_into()?;
        let properties = decode_ack_properties(src)?;
        ensure!(!src.has_remaining(), ParseError::InvalidLength); // no bytes should be left
        (reason_code, properties)
    } else {
        (PublishAckReasonCode::Success, AckProperties::default())
    };

    Ok(PublishAck {
        packet_id,
        reason_code,
        properties,
    })
}

fn decode_publish_ack2(src: &mut Bytes) -> Result<PublishAck2, ParseError> {
    let packet_id = NonZeroU16::parse(src)?;
    let (reason_code, properties) = if src.has_remaining() {
        let reason_code = src.get_u8().try_into()?;
        let properties = decode_ack_properties(src)?;
        ensure!(!src.has_remaining(), ParseError::InvalidLength); // no bytes should be left
        (reason_code, properties)
    } else {
        (PublishAck2ReasonCode::Success, AckProperties::default())
    };

    Ok(PublishAck2 {
        packet_id,
        reason_code,
        properties,
    })
}

fn decode_ack_properties(src: &mut Bytes) -> Result<AckProperties, ParseError> {
    let prop_src = &mut take_properties(src)?;
    let mut reason_string = None;
    let mut user_props = Vec::new();
    while prop_src.has_remaining() {
        let prop_id = prop_src.get_u8();
        match prop_id {
            pt::REASON_STRING => reason_string.read_value(prop_src)?,
            pt::USER => user_props.push(<(ByteStr, ByteStr)>::parse(prop_src)?),
            _ => return Err(ParseError::MalformedPacket),
        }
    }

    Ok(AckProperties {
        reason_string,
        user_properties: user_props,
    })
}

fn decode_subscribe_packet(src: &mut Bytes) -> Result<Packet, ParseError> {
    let packet_id = NonZeroU16::parse(src)?;
    let prop_src = &mut take_properties(src)?;
    let mut sub_id = None;
    let mut user_properties = Vec::new();
    while prop_src.has_remaining() {
        let prop_id = prop_src.get_u8();
        match prop_id {
            pt::SUB_ID => {
                ensure!(sub_id.is_none(), ParseError::MalformedPacket); // can't appear twice
                let val = decode_variable_length_cursor(prop_src)?;
                sub_id = Some(NonZeroU32::new(val).ok_or(ParseError::MalformedPacket)?);
            }
            pt::USER => user_properties.push(UserProperty::parse(prop_src)?),
            _ => return Err(ParseError::MalformedPacket),
        }
    }

    let mut topic_filters = Vec::new();
    while src.has_remaining() {
        let topic = ByteStr::parse(src)?;
        let qos = SubscriptionOptions::parse(src)?;
        topic_filters.push((topic, qos));
    }

    Ok(Packet::Subscribe(Subscribe {
        packet_id,
        id: sub_id,
        user_properties,
        topic_filters,
    }))
}

fn decode_subscribe_ack_packet(src: &mut Bytes) -> Result<Packet, ParseError> {
    let packet_id = NonZeroU16::parse(src)?;
    let properties = decode_ack_properties(src)?;
    let mut status = Vec::with_capacity(src.remaining());
    for code in src.as_ref().iter().copied() {
        status.push(code.try_into()?);
    }
    Ok(Packet::SubscribeAck(SubscribeAck {
        packet_id,
        properties,
        status,
    }))
}

fn decode_unsubscribe_packet(src: &mut Bytes) -> Result<Packet, ParseError> {
    let packet_id = NonZeroU16::parse(src)?;

    let prop_src = &mut take_properties(src)?;
    let mut user_properties = Vec::new();
    while prop_src.has_remaining() {
        let prop_id = prop_src.get_u8();
        match prop_id {
            pt::USER => user_properties.push(UserProperty::parse(prop_src)?),
            _ => return Err(ParseError::MalformedPacket),
        }
    }

    let mut topic_filters = Vec::new();
    while src.remaining() > 0 {
        topic_filters.push(ByteStr::parse(src)?);
    }

    Ok(Packet::Unsubscribe(Unsubscribe {
        packet_id,
        user_properties,
        topic_filters,
    }))
}

fn decode_unsubscribe_ack_packet(src: &mut Bytes) -> Result<Packet, ParseError> {
    let packet_id = NonZeroU16::parse(src)?;
    let properties = decode_ack_properties(src)?;
    let mut status = Vec::with_capacity(src.remaining());
    for code in src.as_ref().iter().copied() {
        status.push(code.try_into()?);
    }
    Ok(Packet::UnsubscribeAck(UnsubscribeAck {
        packet_id,
        properties,
        status,
    }))
}

fn take_properties(src: &mut Bytes) -> Result<BufTake<&mut Bytes>, ParseError> {
    let prop_len = decode_variable_length_cursor(src)?;
    ensure!(
        src.remaining() >= prop_len as usize,
        ParseError::InvalidLength
    );

    Ok(src.take(prop_len as usize))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytestring::ByteString;
    use std::io::Cursor;

    fn packet_id(v: u16) -> NonZeroU16 {
        NonZeroU16::new(v).unwrap()
    }

    fn assert_decode_packet<B: AsRef<[u8]>>(bytes: B, res: Packet) {
        let bytes = bytes.as_ref();
        let fixed = bytes[0];
        let (len, consumed) = decode_variable_length(&bytes[1..]).unwrap().unwrap();
        let hdr = FixedHeader {
            first_byte: fixed,
            remaining_length: (bytes.len() - consumed - 1) as u32,
        };
        let cur = Bytes::copy_from_slice(&bytes[consumed + 1..]);
        assert_eq!(read_packet(cur, hdr), Ok(res));
    }

    #[test]
    fn test_decode_variable_length() {
        fn assert_variable_length<B: AsRef<[u8]> + 'static>(bytes: B, res: (u32, usize)) {
            assert_eq!(decode_variable_length(bytes.as_ref()), Ok(Some(res)));
        }

        assert_variable_length(b"\x7f\x7f", (127, 1));

        assert_eq!(decode_variable_length(b"\xff\xff\xff"), Ok(None));

        assert_eq!(
            decode_variable_length(b"\xff\xff\xff\xff\xff\xff"),
            Err(ParseError::InvalidLength)
        );

        assert_variable_length(b"\x00", (0, 1));
        assert_variable_length(b"\x7f", (127, 1));
        assert_variable_length(b"\x80\x01", (128, 2));
        assert_variable_length(b"\xff\x7f", (16383, 2));
        assert_variable_length(b"\x80\x80\x01", (16384, 3));
        assert_variable_length(b"\xff\xff\x7f", (2_097_151, 3));
        assert_variable_length(b"\x80\x80\x80\x01", (2_097_152, 4));
        assert_variable_length(b"\xff\xff\xff\x7f", (268_435_455, 4));
    }

    #[test]
    fn test_decode_connect_packets() {
        assert_eq!(
            decode_connect_packet(&mut Bytes::from_static(
                b"\x00\x04MQTT\x05\xC0\x00\x3C\x00\x0512345\x00\x04user\x00\x04pass"
            )),
            Ok(Packet::Connect(Connect {
                protocol: Protocol::MQTT(5),
                clean_start: false,
                keep_alive: 60,
                client_id: ByteString::from_static("12345"),
                last_will: None,
                username: Some(ByteString::from_static("user")),
                password: Some(Bytes::from_static(&b"pass"[..])),
                session_expiry_interval_secs: None,
                auth_method: None,
                auth_data: None,
                request_problem_info: None,
                request_response_info: None,
                receive_max: None,
                topic_alias_max: 0,
                user_properties: Vec::new(),
                max_packet_size: None,
            }))
        );

        assert_eq!(
            decode_connect_packet(&mut Bytes::from_static(
                b"\x00\x04MQTT\x04\x14\x00\x3C\x00\x0512345\x00\x05topic\x00\x07message"
            )),
            Ok(Packet::Connect(Connect {
                protocol: Protocol::MQTT(4),
                clean_start: false,
                keep_alive: 60,
                client_id: ByteString::from_static("12345"),
                last_will: Some(LastWill {
                    qos: QoS::ExactlyOnce,
                    retain: false,
                    topic: ByteString::from_static("topic"),
                    message: Bytes::from_static(&b"message"[..]),
                    will_delay_interval_sec: None,
                    correlation_data: None,
                    message_expiry_interval: None,
                    content_type: None,
                    user_properties: Vec::new(),
                    is_utf8_payload: None,
                    response_topic: None,
                }),
                username: None,
                password: None,
                session_expiry_interval_secs: None,
                auth_method: None,
                auth_data: None,
                request_problem_info: None,
                request_response_info: None,
                receive_max: None,
                topic_alias_max: 0,
                user_properties: Vec::new(),
                max_packet_size: None,
            }))
        );

        assert_eq!(
            decode_connect_packet(&mut Bytes::from_static(b"\x00\x02MQ00000000000000000000")),
            Err(ParseError::InvalidProtocol),
        );
        assert_eq!(
            decode_connect_packet(&mut Bytes::from_static(b"\x00\x04MQAA00000000000000000000")),
            Err(ParseError::InvalidProtocol),
        );
        assert_eq!(
            decode_connect_packet(&mut Bytes::from_static(
                b"\x00\x04MQTT\x0300000000000000000000"
            )),
            Err(ParseError::UnsupportedProtocolLevel),
        );
        assert_eq!(
            decode_connect_packet(&mut Bytes::from_static(
                b"\x00\x04MQTT\x04\xff00000000000000000000"
            )),
            Err(ParseError::ConnectReservedFlagSet)
        );

        assert_eq!(
            decode_connect_ack_packet(&mut Bytes::from_static(b"\x01\x04")),
            Ok(Packet::ConnectAck(ConnectAck {
                session_present: true,
                reason_code: ConnectAckReasonCode::BadUserNameOrPassword,
                ..ConnectAck::default()
            }))
        );

        assert_eq!(
            decode_connect_ack_packet(&mut Bytes::from_static(b"\x03\x04")),
            Err(ParseError::ConnAckReservedFlagSet)
        );

        assert_decode_packet(
            b"\x20\x02\x01\x04",
            Packet::ConnectAck(ConnectAck {
                session_present: true,
                reason_code: ConnectAckReasonCode::BadUserNameOrPassword,
                ..ConnectAck::default()
            }),
        );

        assert_decode_packet(&[0b1110_0000, 0], Packet::Disconnect(Disconnect::default()));
    }

    #[test]
    fn test_decode_publish_packets() {
        //assert_eq!(
        //    decode_publish_packet(b"\x00\x05topic\x12\x34"),
        //    Done(&b""[..], ("topic".to_owned(), 0x1234))
        //);

        assert_decode_packet(
            b"\x3d\x0D\x00\x05topic\x43\x21data",
            Packet::Publish(Publish {
                dup: true,
                retain: true,
                qos: QoS::ExactlyOnce,
                topic: ByteString::from_static("topic"),
                packet_id: Some(packet_id(0x4321)),
                payload: Bytes::from_static(b"data"),
                ..Publish::default()
            }),
        );
        assert_decode_packet(
            b"\x30\x0b\x00\x05topicdata",
            Packet::Publish(Publish {
                dup: false,
                retain: false,
                qos: QoS::AtMostOnce,
                topic: ByteString::from_static("topic"),
                packet_id: None,
                payload: Bytes::from_static(b"data"),
                ..Publish::default()
            }),
        );

        assert_decode_packet(
            b"\x40\x02\x43\x21",
            Packet::PublishAck(PublishAck {
                packet_id: packet_id(0x4321),
                reason_code: PublishAckReasonCode::Success,
                properties: AckProperties::default(),
            }),
        );
        assert_decode_packet(
            b"\x50\x02\x43\x21",
            Packet::PublishReceived(PublishAck {
                packet_id: packet_id(0x4321),
                reason_code: PublishAckReasonCode::Success,
                properties: AckProperties::default(),
            }),
        );
        assert_decode_packet(
            b"\x60\x02\x43\x21",
            Packet::PublishRelease(PublishAck2 {
                packet_id: packet_id(0x4321),
                reason_code: PublishAck2ReasonCode::Success,
                properties: AckProperties::default(),
            }),
        );
        assert_decode_packet(
            b"\x70\x02\x43\x21",
            Packet::PublishComplete(PublishAck2 {
                packet_id: packet_id(0x4321),
                reason_code: PublishAck2ReasonCode::Success,
                properties: AckProperties::default(),
            }),
        );
    }

    #[test]
    fn test_decode_subscribe_packets() {
        let p = Packet::Subscribe(Subscribe {
            packet_id: packet_id(0x1234),
            topic_filters: vec![
                (
                    ByteString::from_static("test"),
                    SubscriptionOptions {
                        qos: QoS::AtLeastOnce,
                        no_local: false,
                        retain_as_published: false,
                        retain_handling: RetainHandling::AtSubscribe,
                    },
                ),
                (
                    ByteString::from_static("filter"),
                    SubscriptionOptions {
                        qos: QoS::ExactlyOnce,
                        no_local: false,
                        retain_as_published: false,
                        retain_handling: RetainHandling::AtSubscribe,
                    },
                ),
            ],
            id: None,
            user_properties: Vec::new(),
        });

        assert_eq!(
            decode_subscribe_packet(&mut Bytes::from_static(
                b"\x12\x34\x00\x04test\x01\x00\x06filter\x02"
            )),
            Ok(p.clone())
        );
        assert_decode_packet(b"\x82\x12\x12\x34\x00\x04test\x01\x00\x06filter\x02", p);

        let p = Packet::SubscribeAck(SubscribeAck {
            packet_id: packet_id(0x1234),
            status: vec![
                SubscribeAckReasonCode::GrantedQos1,
                SubscribeAckReasonCode::UnspecifiedError,
                SubscribeAckReasonCode::GrantedQos2,
            ],
            properties: AckProperties::default(),
        });

        assert_eq!(
            decode_subscribe_ack_packet(
                &mut Bytes::from_static(b"\x12\x34\x01\x80\x02")
            ),
            Ok(p.clone())
        );
        assert_decode_packet(b"\x90\x05\x12\x34\x01\x80\x02", p);

        let p = Packet::Unsubscribe(Unsubscribe {
            packet_id: packet_id(0x1234),
            topic_filters: vec![
                ByteString::from_static("test"),
                ByteString::from_static("filter"),
            ],
            user_properties: UserProperties::default(),
        });

        assert_eq!(
            decode_unsubscribe_packet(&mut Bytes::from_static(
                b"\x12\x34\x00\x04test\x00\x06filter"
            )),
            Ok(p.clone())
        );
        assert_decode_packet(b"\xa2\x10\x12\x34\x00\x04test\x00\x06filter", p);

        assert_decode_packet(
            b"\xb0\x02\x43\x21",
            Packet::UnsubscribeAck(UnsubscribeAck {
                packet_id: packet_id(0x4321),
                properties: AckProperties::default(),
                status: vec![],
            }),
        );
    }

    #[test]
    fn test_decode_ping_packets() {
        assert_decode_packet(b"\xc0\x00", Packet::PingRequest);
        assert_decode_packet(b"\xd0\x00", Packet::PingResponse);
    }
}
