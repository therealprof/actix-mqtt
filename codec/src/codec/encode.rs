use super::{ConnectFlags, WILL_QOS_SHIFT};
use super::{Encode, EncodeLtd};
use crate::error::ParseError;
use crate::packet::property_type as pt;
use crate::packet::*;
use crate::proto::*;
use bytes::{BufMut, Bytes, BytesMut};
use std::num::{NonZeroU16, NonZeroU32};

impl EncodeLtd for Packet {
    fn encoded_size(&self, limit: u32) -> u32 {
        // limit -= 5; // fixed header = 1, var_len(remaining.max_value()) = 4
        match self {
            Packet::Connect(connect) => connect.encoded_size(limit),
            Packet::Publish(publish) => publish.encoded_size(limit),
            Packet::ConnectAck(ack) => ack.encoded_size(limit),
            Packet::PublishAck(ack) | Packet::PublishReceived(ack) => ack.encoded_size(limit),
            Packet::PublishRelease(ack) | Packet::PublishComplete(ack) => {
                ack.encoded_size(limit)
            }

            Packet::Subscribe(sub) => {
                2 + sub
                    .topic_filters // todo: add properties, move to impl EncodeLtd instead
                    .iter()
                    .fold(0u32, |acc, &(ref filter, _)| {
                        acc + 2 + filter.len() as u32 + 1
                    })
            }

            Packet::SubscribeAck(ack) => ack.encoded_size(limit),
            Packet::Unsubscribe(unsub) => unsub.encoded_size(limit),
            Packet::UnsubscribeAck(ack) => ack.encoded_size(limit),
            Packet::PingRequest | Packet::PingResponse => 0,
            Packet::Disconnect(disconnect) => disconnect.encoded_size(limit),
            Packet::Auth(auth) => auth.encoded_size(limit),
        }
    }

    fn encode(&self, buf: &mut BytesMut, check_size: u32) -> Result<(), ParseError> {
        match self {
            Packet::Connect(connect) => {
                buf.put_u8(0b0001_0000);
                write_variable_length(check_size, buf);
                connect.encode(buf, check_size)
            }
            Packet::ConnectAck(ack) => {
                buf.put_u8(0b0010_0000);
                write_variable_length(check_size, buf);
                ack.encode(buf, check_size)
            }
            Packet::Publish(publish) => {
                buf.put_u8(
                    0b0011_0000
                        | (u8::from(publish.qos) << 1)
                        | ((publish.dup as u8) << 3)
                        | (publish.retain as u8),
                );
                write_variable_length(check_size, buf);
                publish.encode(buf, check_size)
            }
            Packet::PublishAck(ack) => {
                buf.put_u8(0b0100_0000);
                write_variable_length(check_size, buf);
                ack.encode(buf, check_size)
            }
            Packet::PublishReceived(ack) => {
                buf.put_u8(0b0101_0000);
                write_variable_length(check_size, buf);
                ack.encode(buf, check_size)
            }
            Packet::PublishRelease(ack) => {
                buf.put_u8(0b0110_0010);
                write_variable_length(check_size, buf);
                ack.encode(buf, check_size)
            }
            Packet::PublishComplete(ack) => {
                buf.put_u8(0b0111_0000);
                write_variable_length(check_size, buf);
                ack.encode(buf, check_size)
            }
            Packet::Subscribe(sub) => {
                buf.put_u8(0b1000_0010);
                write_variable_length(check_size, buf);
                sub.encode(buf, check_size)
            }
            Packet::SubscribeAck(ack) => {
                buf.put_u8(0b1001_0000);
                write_variable_length(check_size, buf);
                ack.encode(buf, check_size)
            }
            Packet::Unsubscribe(unsub) => {
                buf.put_u8(0b1010_0010);
                write_variable_length(check_size, buf);
                unsub.encode(buf, check_size)
            }
            Packet::UnsubscribeAck(ack) => {
                buf.put_u8(0b1011_0000);
                write_variable_length(check_size, buf);
                ack.encode(buf, check_size)
            }
            Packet::PingRequest => {
                buf.put_slice(&[0b1100_0000, 0]);
                Ok(())
            }
            Packet::PingResponse => {
                buf.put_slice(&[0b1101_0000, 0]);
                Ok(())
            }
            Packet::Disconnect(disconnect) => {
                buf.put_u8(0b1110_0000);
                write_variable_length(check_size, buf);
                disconnect.encode(buf, check_size)
            }
            Packet::Auth(auth) => {
                buf.put_u8(0b1111_0000);
                write_variable_length(check_size, buf);
                auth.encode(buf, check_size)
            }
        }
    }
}

impl LastWill {
    fn properties_len(&self) -> u32 {
        encoded_property_size(&self.will_delay_interval_sec)
            + encoded_property_size(&self.correlation_data)
            + encoded_property_size(&self.message_expiry_interval)
            + encoded_property_size(&self.content_type)
            + encoded_property_size(&self.is_utf8_payload)
            + encoded_property_size(&self.response_topic)
            + self.user_properties.encoded_size()
    }
}

impl Connect {
    fn properties_len(&self) -> u32 {
        let mut prop_len = encoded_property_size(&self.session_expiry_interval_secs)
            + encoded_property_size(&self.auth_method)
            + encoded_property_size(&self.auth_data)
            + encoded_property_size(&self.request_problem_info)
            + encoded_property_size(&self.request_response_info)
            + encoded_property_size(&self.receive_max)
            + encoded_property_size(&self.max_packet_size)
            + self.user_properties.encoded_size();
        if self.topic_alias_max > 0 {
            prop_len += 1 + self.topic_alias_max.encoded_size(); // [property type, value..]
        }
        prop_len
    }
}

impl EncodeLtd for Connect {
    fn encoded_size(&self, _limit: u32) -> u32 {
        let prop_len = self.properties_len();
        6 // protocol name
            + 1 // protocol level
            + 1 // connect flags
            + 2 // keep alive
            + var_int_len(prop_len) // properties len
            + prop_len // properties
            + self.client_id.encoded_size()
            + self.last_will.as_ref().map_or(0, |will| { // will message content
                let prop_len = will.properties_len();
                var_int_len(prop_len) + prop_len + will.topic.encoded_size() + will.message.encoded_size()
            })
            + self.username.as_ref().map_or(0, |v| v.encoded_size())
            + self.password.as_ref().map_or(0, |v| v.encoded_size())
    }

    fn encode(&self, buf: &mut BytesMut, _size: u32) -> Result<(), ParseError> {
        Bytes::from(self.protocol.name().as_bytes()).encode(buf)?;

        let mut flags = ConnectFlags::empty();

        if self.username.is_some() {
            flags |= ConnectFlags::USERNAME;
        }
        if self.password.is_some() {
            flags |= ConnectFlags::PASSWORD;
        }

        if let Some(will) = self.last_will.as_ref() {
            flags |= ConnectFlags::WILL;

            if will.retain {
                flags |= ConnectFlags::WILL_RETAIN;
            }

            flags |= ConnectFlags::from_bits_truncate(u8::from(will.qos) << WILL_QOS_SHIFT);
        }

        if self.clean_start {
            flags |= ConnectFlags::CLEAN_START;
        }

        buf.put_slice(&[self.protocol.level(), flags.bits()]);

        self.keep_alive.encode(buf)?;

        let prop_len = self.properties_len();
        write_variable_length(prop_len, buf);
        encode_property(&self.session_expiry_interval_secs, pt::SESS_EXPIRY_INT, buf)?;
        encode_property(&self.auth_method, pt::AUTH_METHOD, buf)?;
        encode_property(&self.auth_data, pt::AUTH_DATA, buf)?;
        encode_property(&self.request_problem_info, pt::REQ_PROB_INFO, buf)?;
        encode_property(&self.request_response_info, pt::REQ_RESP_INFO, buf)?;
        encode_property(&self.receive_max, pt::RECEIVE_MAX, buf)?;
        encode_property(&self.max_packet_size, pt::MAX_PACKET_SIZE, buf)?;
        if self.topic_alias_max > 0 {
            buf.put_u8(pt::TOPIC_ALIAS_MAX);
            self.topic_alias_max.encode(buf)?;
        }
        self.user_properties.encode(buf)?;

        self.client_id.encode(buf)?;

        if let Some(will) = self.last_will.as_ref() {
            let prop_len = will.properties_len();
            write_variable_length(prop_len, buf);

            will.topic.encode(buf)?;
            will.message.encode(buf)?;
        }
        if let Some(s) = self.username.as_ref() {
            s.encode(buf)?;
        }
        if let Some(pwd) = self.password.as_ref() {
            pwd.encode(buf)?;
        }
        Ok(())
    }
}

impl EncodeLtd for ConnectAck {
    fn encoded_size(&self, limit: u32) -> u32 {
        const HEADER_LEN: u32 = 2; // state flags byte + reason code

        let mut prop_len = encoded_property_size(&self.session_expiry_interval_secs)
            + encoded_property_size(&self.receive_max)
            + self.max_qos.map_or(0, |_| 1 + 1) // [property type, value]
            + encoded_property_size(&self.retain_available)
            + encoded_property_size(&self.max_packet_size)
            + encoded_property_size(&self.assigned_client_id)
            + encoded_property_size(&self.wildcard_subscription_available)
            + encoded_property_size(&self.subscription_identifiers_available)
            + encoded_property_size(&self.shared_subscription_available)
            + encoded_property_size(&self.server_keepalive_sec)
            + encoded_property_size(&self.response_info)
            + encoded_property_size(&self.server_reference)
            + encoded_property_size(&self.auth_method)
            + encoded_property_size(&self.auth_data);
        if self.topic_alias_max > 0 {
            prop_len += 1 + self.topic_alias_max.encoded_size(); // [property type, value..]
        }

        let diag_len = encoded_size_opt_props(
            &self.user_properties,
            &self.reason_string,
            limit - prop_len - HEADER_LEN - 4,
        ); // exclude other props and max of 4 bytes for property length value
        prop_len += diag_len;
        HEADER_LEN + var_int_len(prop_len) + prop_len
    }

    fn encode(&self, buf: &mut BytesMut, size: u32) -> Result<(), ParseError> {
        // todo: move upstream: write_variable_length(size, buf);
        buf.put_slice(&[
            if self.session_present { 0x01 } else { 0x00 },
            self.reason_code.into(),
        ]);

        let prop_len = var_int_len_from_size(size - 2);
        write_variable_length(prop_len, buf);

        encode_property(&self.session_expiry_interval_secs, pt::SESS_EXPIRY_INT, buf)?;
        encode_property(&self.receive_max, pt::RECEIVE_MAX, buf)?;
        if let Some(max_qos) = self.max_qos {
            buf.put_slice(&[pt::MAX_QOS, max_qos.into()]);
        }
        encode_property(&self.retain_available, pt::RETAIN_AVAIL, buf)?;
        encode_property(&self.max_packet_size, pt::MAX_PACKET_SIZE, buf)?;
        encode_property(&self.assigned_client_id, pt::ASSND_CLIENT_ID, buf)?;
        if self.topic_alias_max > 0 {
            buf.put_u8(pt::TOPIC_ALIAS_MAX);
            self.topic_alias_max.encode(buf)?;
        }
        encode_property(
            &self.wildcard_subscription_available,
            pt::WILDCARD_SUB_AVAIL,
            buf,
        )?;
        encode_property(
            &self.subscription_identifiers_available,
            pt::SUB_IDS_AVAIL,
            buf,
        )?;
        encode_property(
            &self.shared_subscription_available,
            pt::SHARED_SUB_AVAIL,
            buf,
        )?;
        encode_property(&self.server_keepalive_sec, pt::SERVER_KA, buf)?;
        encode_property(&self.response_info, pt::RESP_INFO, buf)?;
        encode_property(&self.server_reference, pt::SERVER_REF, buf)?;
        encode_property(&self.auth_method, pt::AUTH_METHOD, buf)?;
        encode_property(&self.auth_data, pt::AUTH_DATA, buf)?;

        encode_opt_props(
            &self.user_properties,
            &self.reason_string,
            buf,
            size - buf.len() as u32,
        )
    }
}

impl EncodeLtd for Disconnect {
    fn encoded_size(&self, limit: u32) -> u32 {
        const HEADER_LEN: u32 = 1; // reason code

        let mut prop_len = encoded_property_size(&self.session_expiry_interval_secs)
            + encoded_property_size(&self.server_reference);
        let diag_len = encoded_size_opt_props(
            &self.user_properties,
            &self.reason_string,
            limit - prop_len - HEADER_LEN - 4,
        ); // exclude other props and max of 4 bytes for property length value
        prop_len += diag_len;
        HEADER_LEN + var_int_len(prop_len) + prop_len
    }

    fn encode(&self, buf: &mut BytesMut, size: u32) -> Result<(), ParseError> {
        buf.put_u8(self.reason_code.into());

        let prop_len = var_int_len_from_size(size - 1);
        write_variable_length(prop_len, buf);
        encode_property(&self.session_expiry_interval_secs, pt::SESS_EXPIRY_INT, buf)?;
        encode_property(&self.server_reference, pt::SERVER_REF, buf)?;
        encode_opt_props(
            &self.user_properties,
            &self.reason_string,
            buf,
            size - buf.len() as u32,
        )
    }
}

impl EncodeLtd for Auth {
    fn encoded_size(&self, limit: u32) -> u32 {
        const HEADER_LEN: u32 = 1; // reason code

        let mut prop_len =
            encoded_property_size(&self.auth_method) + encoded_property_size(&self.auth_data);
        let diag_len = encoded_size_opt_props(
            &self.user_properties,
            &self.reason_string,
            limit - prop_len - HEADER_LEN - 4,
        ); // exclude other props and max of 4 bytes for property length value
        prop_len += diag_len;
        HEADER_LEN + var_int_len(prop_len) + prop_len
    }

    fn encode(&self, buf: &mut BytesMut, size: u32) -> Result<(), ParseError> {
        buf.put_u8(self.reason_code.into());

        let prop_len = var_int_len_from_size(size - 1);
        write_variable_length(prop_len, buf);
        encode_property(&self.auth_method, pt::AUTH_METHOD, buf)?;
        encode_property(&self.auth_data, pt::AUTH_DATA, buf)?;
        encode_opt_props(
            &self.user_properties,
            &self.reason_string,
            buf,
            size - buf.len() as u32,
        )
    }
}

impl EncodeLtd for Subscribe {
    fn encoded_size(&self, _limit: u32) -> u32 {
        let prop_len =
            self.id.map_or(0, |v| var_int_len(v.get())) + self.user_properties.encoded_size();
        let payload_len = self
            .topic_filters
            .iter()
            .fold(0, |acc, (filter, _opts)| acc + filter.encoded_size() + 1);
        self.packet_id.encoded_size() + var_int_len(prop_len) + prop_len + payload_len
    }

    fn encode(&self, buf: &mut BytesMut, size: u32) -> Result<(), ParseError> {
        self.packet_id.encode(buf)?;

        let prop_len = var_int_len_from_size(size - 2);
        write_variable_length(prop_len, buf);
        encode_property(&self.id, pt::SUB_ID, buf)?;
        for (filter, opts) in self.topic_filters.iter() {
            filter.encode(buf)?;
            opts.encode(buf)?;
        }

        Ok(())
    }
}

impl Encode for SubscriptionOptions {
    fn encoded_size(&self) -> u32 {
        1
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError> {
        buf.put_u8(
            u8::from(self.qos)
                | (self.no_local as u8) << 2
                | (self.retain_as_published as u8) << 3
                | u8::from(self.retain_handling) << 4,
        );
        Ok(())
    }
}

impl EncodeLtd for SubscribeAck {
    fn encoded_size(&self, limit: u32) -> u32 {
        let len = self.status.len() as u32;
        2 + self.properties.encoded_size(limit - 2 - len) + len
    }

    fn encode(&self, buf: &mut BytesMut, size: u32) -> Result<(), ParseError> {
        self.packet_id.encode(buf)?;
        let len = self.status.len() as u32;
        self.properties.encode(buf, size - 2 - len)?;
        for &reason in self.status.iter() {
            buf.put_u8(reason.into());
        }
        Ok(())
    }
}

impl EncodeLtd for Unsubscribe {
    fn encoded_size(&self, _limit: u32) -> u32 {
        let prop_len = self.user_properties.encoded_size();
        2 + var_int_len(prop_len)
            + prop_len
            + self
                .topic_filters
                .iter()
                .fold(0, |acc, filter| acc + 2 + filter.len() as u32)
    }

    fn encode(&self, buf: &mut BytesMut, _size: u32) -> Result<(), ParseError> {
        self.packet_id.encode(buf)?;
        let prop_len = self.user_properties.encoded_size();
        write_variable_length(prop_len, buf);
        for filter in self.topic_filters.iter() {
            filter.encode(buf)?;
        }
        Ok(())
    }
}

impl EncodeLtd for UnsubscribeAck {
    // todo: almost identical to SUBACK
    fn encoded_size(&self, limit: u32) -> u32 {
        let len = self.status.len() as u32;
        2 + len + self.properties.encoded_size(limit - 2 - len) // limit
    }

    fn encode(&self, buf: &mut BytesMut, size: u32) -> Result<(), ParseError> {
        self.packet_id.encode(buf)?;
        let len = self.status.len() as u32;

        self.properties.encode(buf, size - 2 - len)?;
        for &reason in self.status.iter() {
            buf.put_u8(reason.into());
        }
        Ok(())
    }
}

impl EncodeLtd for Publish {
    fn encoded_size(&self, _limit: u32) -> u32 {
        let packet_id_size = if self.qos == QoS::AtMostOnce { 0 } else { 2 };
        self.topic.encoded_size()
            + packet_id_size
            + self.properties.encoded_size(_limit)
            + self.payload.len() as u32
    }

    fn encode(&self, buf: &mut BytesMut, size: u32) -> Result<(), ParseError> {
        self.topic.encode(buf)?;
        if self.qos != QoS::AtMostOnce {
            // todo: check that packet_id is not set if QoS = 0?
            self.packet_id
                .ok_or(ParseError::PacketIdRequired)?
                .encode(buf)?;
        }
        self.properties
            .encode(buf, size - (buf.len() + self.payload.len()) as u32)?;
        buf.put(self.payload.as_ref());
        Ok(())
    }
}

impl EncodeLtd for PublishProperties {
    fn encoded_size(&self, _limit: u32) -> u32 {
        let prop_len = encoded_property_size(&self.topic_alias)
            + encoded_property_size(&self.correlation_data)
            + encoded_property_size(&self.message_expiry_interval)
            + encoded_property_size(&self.content_type)
            + encoded_property_size(&self.is_utf8_payload)
            + encoded_property_size(&self.response_topic)
            + self.subscription_ids.as_ref().map_or(0, |v| {
                v.iter().fold(0, |acc, id| acc + 1 + var_int_len(id.get()))
            })
            + self.user_properties.encoded_size();
        prop_len + var_int_len(prop_len)
    }

    fn encode(&self, buf: &mut BytesMut, size: u32) -> Result<(), ParseError> {
        let prop_len = var_int_len_from_size(size);
        write_variable_length(prop_len, buf);
        encode_property(&self.topic_alias, pt::TOPIC_ALIAS, buf)?;
        encode_property(&self.correlation_data, pt::CORR_DATA, buf)?;
        encode_property(&self.message_expiry_interval, pt::MSG_EXPIRY_INT, buf)?;
        encode_property(&self.content_type, pt::CONTENT_TYPE, buf)?;
        encode_property(&self.is_utf8_payload, pt::UTF8_PAYLOAD, buf)?;
        encode_property(&self.response_topic, pt::RESP_TOPIC, buf)?;
        if let Some(sub_ids) = self.subscription_ids.as_ref() {
            for sub_id in sub_ids.iter() {
                buf.put_u8(pt::SUB_ID);
                sub_id.encode(buf)?;
            }
        }
        self.user_properties.encode(buf)
    }
}

impl EncodeLtd for PublishAck {
    fn encoded_size(&self, limit: u32) -> u32 {
        const HEADER_LEN: u32 = 2 + 1; // packet id + reason code
        let prop_len = self.properties.encoded_size(limit - HEADER_LEN - 4); // limit - HEADER_LEN - len(packet_len.max())
        HEADER_LEN + prop_len
    }

    fn encode(&self, buf: &mut BytesMut, size: u32) -> Result<(), ParseError> {
        write_variable_length(size, buf);
        self.packet_id.get().encode(buf)?;
        buf.put_u8(self.reason_code.into());
        self.properties.encode(buf, size - 3)?;
        Ok(())
    }
}

impl EncodeLtd for PublishAck2 {
    fn encoded_size(&self, limit: u32) -> u32 {
        const HEADER_LEN: u32 = 2 + 1; // fixed header + packet id + reason code
        let prop_len = self.properties.encoded_size(limit - HEADER_LEN - 4); // limit - HEADER_LEN - packet_len.max()
        HEADER_LEN + prop_len
    }

    fn encode(&self, buf: &mut BytesMut, size: u32) -> Result<(), ParseError> {
        write_variable_length(size, buf);
        self.packet_id.get().encode(buf)?;
        buf.put_u8(self.reason_code.into());
        self.properties.encode(buf, size - 3)?;
        Ok(())
    }
}

impl EncodeLtd for AckProperties {
    fn encoded_size(&self, limit: u32) -> u32 {
        if limit < 4 {
            // todo: not really needed in practice
            return 1; // 1 byte to encode property length = 0
        }

        let len = encoded_size_opt_props(&self.user_properties, &self.reason_string, limit - 4);
        var_int_len(len) + len
    }

    fn encode(&self, buf: &mut BytesMut, size: u32) -> Result<(), ParseError> {
        debug_assert!(size > 0); // formalize in signature?

        if size == 1 {
            // empty properties
            buf.put_u8(0);
            return Ok(());
        }

        let size = var_int_len_from_size(size);
        write_variable_length(size, buf);
        encode_opt_props(&self.user_properties, &self.reason_string, buf, size)
    }
}

fn encoded_size_opt_props(
    user_props: &UserProperties,
    reason_str: &Option<ByteStr>,
    mut limit: u32,
) -> u32 {
    let mut len = 0;
    for up in user_props.iter() {
        let prop_len = 1 + up.encoded_size(); // prop type byte + key.len() + val.len()
        if prop_len > limit {
            return len;
        }
        limit -= prop_len;
        len += prop_len;
    }

    if let Some(reason) = reason_str {
        let reason_len = reason.len() as u32 + 1; // safety: TODO: CHECK string length for being out of bounds (> u16::max_value())?
        if reason_len <= limit {
            len += reason_len;
        }
    }

    len
}

fn encode_opt_props(
    user_props: &UserProperties,
    reason_str: &Option<ByteStr>,
    buf: &mut BytesMut,
    mut size: u32,
) -> Result<(), ParseError> {
    for up in user_props.iter() {
        let prop_len = 1 + up.0.encoded_size() + up.1.encoded_size(); // prop_type.len() + key.len() + val.len()
        if prop_len > size {
            return Ok(());
        }
        buf.put_u8(pt::USER);
        up.encode(buf)?;
        size -= prop_len;
    }

    if let Some(reason) = reason_str {
        if reason.len() < size as usize {
            buf.put_u8(pt::REASON_STRING);
            reason.encode(buf)?;
        }
    }

    // todo: debug_assert remaining is 0

    Ok(())
}

fn encoded_property_size<T: Encode>(v: &Option<T>) -> u32 {
    v.as_ref().map_or(0, |v| 1 + v.encoded_size()) // 1 - property type byte
}

fn encode_property<T: Encode>(
    v: &Option<T>,
    prop_type: u8,
    buf: &mut BytesMut,
) -> Result<(), ParseError> {
    if let Some(v) = v {
        buf.put_u8(prop_type);
        v.encode(buf)
    } else {
        Ok(())
    }
}

/// Calculates length of variable length integer based on its value
fn var_int_len(val: u32) -> u32 {
    const MAP: [u32; 33] = [
        5, 5, 5, 5, 4, 4, 4, 4, 4, 4, 4, 3, 3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1,
        1, 1, 1, 1,
    ];
    let zeros = val.leading_zeros();
    unsafe { *MAP.get_unchecked(zeros as usize) } // safety: zeros will never be more than 32 by definition.
}

/// Calculates `len` from `var_int_len(len) + len` value
fn var_int_len_from_size(val: u32) -> u32 {
    let over_size = var_int_len(val);
    let res = val - over_size + 1;
    val - var_int_len(res)
}

fn write_variable_length(size: u32, dst: &mut BytesMut) {
    match size {
        0..=127 => dst.put_u8(size as u8),
        128..=16_383 => dst.put_slice(&[
            ((size & 0b0111_1111) | 0b1000_0000) as u8,
            (size >> 7) as u8,
        ]),
        16_384..=2_097_151 => {
            dst.put_slice(&[
                ((size & 0b0111_1111) | 0b1000_0000) as u8,
                (((size >> 7) & 0b0111_1111) | 0b1000_0000) as u8,
                (size >> 14) as u8,
            ]);
        }
        2_097_152..=268_435_455 => {
            dst.put_slice(&[
                ((size & 0b0111_1111) | 0b1000_0000) as u8,
                (((size >> 7) & 0b0111_1111) | 0b1000_0000) as u8,
                (((size >> 14) & 0b0111_1111) | 0b1000_0000) as u8,
                (size >> 21) as u8,
            ]);
        }
        _ => panic!("length is too big"), // todo: verify at higher level
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encoded_size(&self) -> u32 {
        if let Some(v) = self {
            v.encoded_size()
        } else {
            0
        }
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError> {
        if let Some(v) = self {
            v.encode(buf)
        } else {
            Ok(())
        }
    }
}

impl Encode for bool {
    fn encoded_size(&self) -> u32 {
        1
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError> {
        if *self {
            buf.put_u8(0x1);
        } else {
            buf.put_u8(0x0);
        }
        Ok(())
    }
}

impl Encode for u16 {
    fn encoded_size(&self) -> u32 {
        2
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError> {
        buf.put_u16(*self);
        Ok(())
    }
}

impl Encode for NonZeroU16 {
    fn encoded_size(&self) -> u32 {
        2
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError> {
        self.get().encode(buf)
    }
}

impl Encode for u32 {
    fn encoded_size(&self) -> u32 {
        4
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError> {
        buf.put_u32(*self);
        Ok(())
    }
}

impl Encode for NonZeroU32 {
    fn encoded_size(&self) -> u32 {
        4
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError> {
        self.get().encode(buf)
    }
}

impl Encode for Bytes {
    fn encoded_size(&self) -> u32 {
        2 + self.len() as u32
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError> {
        buf.put_u16(self.len() as u16);
        buf.extend_from_slice(self.as_ref());
        Ok(())
    }
}

impl Encode for ByteStr {
    fn encoded_size(&self) -> u32 {
        self.get_ref().encoded_size()
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError> {
        self.get_ref().encode(buf)
    }
}

impl Encode for (ByteStr, ByteStr) {
    fn encoded_size(&self) -> u32 {
        self.0.encoded_size() + self.1.encoded_size()
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError> {
        self.0.encode(buf)?;
        self.1.encode(buf)
    }
}

impl Encode for UserProperties {
    fn encoded_size(&self) -> u32 {
        let mut len = 0;
        for prop in self {
            len += 1 + prop.encoded_size();
        }
        len
    }
    fn encode(&self, buf: &mut BytesMut) -> Result<(), ParseError> {
        for prop in self {
            buf.put_u8(pt::USER);
            prop.encode(buf)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use bytestring::ByteString;

    use super::*;
    use crate::codec::EncodeLtd;
    use crate::codec::MAX_PACKET_SIZE;

    fn packet_id(v: u16) -> NonZeroU16 {
        NonZeroU16::new(v).unwrap()
    }

    #[test]
    fn test_encode_variable_length() {
        let mut v = BytesMut::new();

        write_variable_length(123, &mut v);
        assert_eq!(v, [123].as_ref());

        v.clear();

        write_variable_length(129, &mut v);
        assert_eq!(v, b"\x81\x01".as_ref());

        v.clear();

        write_variable_length(16_383, &mut v);
        assert_eq!(v, b"\xff\x7f".as_ref());

        v.clear();

        write_variable_length(2_097_151, &mut v);
        assert_eq!(v, b"\xff\xff\x7f".as_ref());

        v.clear();

        write_variable_length(268_435_455, &mut v);
        assert_eq!(v, b"\xff\xff\xff\x7f".as_ref());

        // assert!(v.write_variable_length(MAX_VARIABLE_LENGTH + 1).is_err())
    }

    #[test]
    fn test_encode_fixed_header() {
        let mut v = BytesMut::new();
        let p = Packet::PingRequest;

        assert_eq!(p.encoded_size(MAX_PACKET_SIZE), 0);
        p.encode(&mut v, 0).unwrap();
        assert_eq!(&v[..2], b"\xc0\x00".as_ref());

        v.clear();

        let p = Packet::Publish(Publish {
            dup: true,
            retain: true,
            qos: QoS::ExactlyOnce,
            topic: ByteString::from_static("topic"),
            packet_id: Some(packet_id(0x4321)),
            payload: (0..255).collect::<Vec<u8>>().into(),
            properties: PublishProperties::default(),
        });

        assert_eq!(p.encoded_size(MAX_PACKET_SIZE), 264);
        p.encode(&mut v, 264);
        assert_eq!(&v[..3], b"\x3d\x88\x02".as_ref());
    }

    macro_rules! assert_packet {
        ($p:expr, $data:expr) => {
            let mut v = BytesMut::with_capacity(1024);
            let x = $p;
            x.encode(&mut v, x.encoded_size(1024));
            assert_eq!(v.len(), $data.len());
            assert_eq!(v, &$data[..]);
            // assert_eq!(read_packet($data.cursor()).unwrap(), (&b""[..], $p));
        };
    }

    #[test]
    fn test_encode_connect_packets() {
        assert_packet!(
            &Packet::Connect(Connect {
                protocol: Protocol::MQTT(5),
                clean_start: false,
                keep_alive: 60,
                client_id: ByteString::from_static("12345"),
                last_will: None,
                username: Some(ByteString::from_static("user")),
                password: Some(Bytes::from_static(b"pass")),
                ..Connect::default()
            }),
            &b"\x10\x1D\x00\x04MQTT\x04\xC0\x00\x3C\x00\
\x0512345\x00\x04user\x00\x04pass"[..]
        );

        assert_packet!(
            &Packet::Connect(Connect {
                protocol: Protocol::MQTT(4),
                clean_start: false,
                keep_alive: 60,
                client_id: ByteString::from_static("12345"),
                last_will: Some(LastWill {
                    qos: QoS::ExactlyOnce,
                    retain: false,
                    topic: ByteString::from_static("topic"),
                    message: Bytes::from_static(b"message"),
                    ..LastWill::default()
                }),
                ..Connect::default()
            }),
            &b"\x10\x21\x00\x04MQTT\x04\x14\x00\x3C\x00\
\x0512345\x00\x05topic\x00\x07message"[..]
        );

        assert_packet!(&Packet::Disconnect(Disconnect::default()), b"\xe0\x00");
    }

    #[test]
    fn test_encode_publish_packets() {
        assert_packet!(
            &Packet::Publish(Publish {
                dup: true,
                retain: true,
                qos: QoS::ExactlyOnce,
                topic: ByteString::from_static("topic"),
                packet_id: Some(packet_id(0x4321)),
                payload: Bytes::from_static(b"data"),
                properties: PublishProperties::default(),
            }),
            b"\x3d\x0D\x00\x05topic\x43\x21data"
        );

        assert_packet!(
            &Packet::Publish(Publish {
                dup: false,
                retain: false,
                qos: QoS::AtMostOnce,
                topic: ByteString::from_static("topic"),
                packet_id: None,
                payload: Bytes::from_static(b"data"),
                properties: PublishProperties::default()
            }),
            b"\x30\x0b\x00\x05topicdata"
        );
    }

    #[test]
    fn test_encode_subscribe_packets() {
        assert_packet!(
            &Packet::Subscribe(Subscribe {
                packet_id: packet_id(0x1234),
                id: None,
                user_properties: Vec::new(),
                topic_filters: vec![
                    (
                        ByteString::from_static("test"),
                        SubscriptionOptions {
                            qos: QoS::AtLeastOnce,
                            no_local: false,
                            retain_as_published: false,
                            retain_handling: RetainHandling::AtSubscribe
                        }
                    ),
                    (
                        ByteString::from_static("filter"),
                        SubscriptionOptions {
                            qos: QoS::ExactlyOnce,
                            no_local: false,
                            retain_as_published: false,
                            retain_handling: RetainHandling::AtSubscribe
                        }
                    )
                ],
            }),
            b"\x82\x12\x12\x34\x00\x04test\x01\x00\x06filter\x02"
        );

        assert_packet!(
            &Packet::SubscribeAck(SubscribeAck {
                packet_id: packet_id(0x1234),
                properties: AckProperties::default(),
                status: vec![
                    SubscribeAckReasonCode::GrantedQos1,
                    SubscribeAckReasonCode::UnspecifiedError,
                    SubscribeAckReasonCode::GrantedQos2,
                ],
            }),
            b"\x90\x05\x12\x34\x01\x80\x02"
        );

        assert_packet!(
            &Packet::Unsubscribe(Unsubscribe {
                packet_id: packet_id(0x1234),
                topic_filters: vec![
                    ByteString::from_static("test"),
                    ByteString::from_static("filter"),
                ],
                user_properties: Vec::new(),
            }),
            b"\xa2\x10\x12\x34\x00\x04test\x00\x06filter"
        );

        assert_packet!(
            &Packet::UnsubscribeAck(UnsubscribeAck {
                packet_id: packet_id(0x4321),
                properties: AckProperties::default(),
                status: vec![
                    UnsubscribeAckReasonCode::Success,
                    UnsubscribeAckReasonCode::NotAuthorized
                ],
            }),
            b"\xb0\x02\x43\x21"
        );
    }

    #[test]
    fn test_encode_ping_packets() {
        assert_packet!(&Packet::PingRequest, b"\xc0\x00");
        assert_packet!(&Packet::PingResponse, b"\xd0\x00");
    }
}
