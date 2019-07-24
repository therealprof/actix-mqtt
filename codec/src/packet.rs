use crate::proto::{Protocol, QoS};
use bytes::Bytes;
use bytestring::ByteString;
use std::num::{NonZeroU16, NonZeroU32};

pub(crate) type ByteStr = ByteString;
pub(crate) type UserProperties = Vec<(ByteStr, ByteStr)>;

#[derive(Debug, PartialEq, Clone)]
/// Connection Will
pub struct LastWill {
    /// the QoS level to be used when publishing the Will Message.
    pub qos: QoS,
    /// the Will Message is to be Retained when it is published.
    pub retain: bool,
    /// the Will Topic
    pub topic: ByteStr,
    /// defines the Application Message that is to be published to the Will Topic
    pub message: Bytes,

    pub will_delay_interval_sec: Option<u32>,
    pub correlation_data: Option<Bytes>,
    pub message_expiry_interval: Option<NonZeroU32>,
    pub content_type: Option<ByteStr>,
    pub user_properties: UserProperties,
    pub is_utf8_payload: Option<bool>,
    pub response_topic: Option<ByteStr>,
}

impl Default for LastWill {
    fn default() -> Self {
        Self {
            qos: QoS::AtMostOnce,
            retain: false,
            topic: ByteStr::default(),
            message: Bytes::default(),
            will_delay_interval_sec: None,
            correlation_data: None,
            message_expiry_interval: None,
            content_type: None,
            user_properties: UserProperties::default(),
            is_utf8_payload: None,
            response_topic: None,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
/// Connect packet content
pub struct Connect {
    /// mqtt protocol version
    pub protocol: Protocol,
    /// the handling of the Session state.
    pub clean_start: bool,
    /// a time interval measured in seconds.
    pub keep_alive: u16,

    pub session_expiry_interval_secs: Option<u32>,
    pub auth_method: Option<ByteStr>,
    pub auth_data: Option<Bytes>,
    pub request_problem_info: Option<bool>,
    pub request_response_info: Option<bool>,
    pub receive_max: Option<NonZeroU16>,
    pub topic_alias_max: u16,
    pub user_properties: UserProperties,
    pub max_packet_size: Option<NonZeroU32>,

    /// Will Message be stored on the Server and associated with the Network Connection.
    pub last_will: Option<LastWill>,
    /// identifies the Client to the Server.
    pub client_id: ByteStr,
    /// username can be used by the Server for authentication and authorization.
    pub username: Option<ByteStr>,
    /// password can be used by the Server for authentication and authorization.
    pub password: Option<Bytes>,
}

impl Default for Connect {
    fn default() -> Self {
        Self {
            protocol: Protocol::MQTT(5),
            clean_start: false,
            keep_alive: 0,
            session_expiry_interval_secs: None,
            auth_method: None,
            auth_data: None,
            request_problem_info: None,
            request_response_info: None,
            receive_max: None,
            topic_alias_max: 0,
            user_properties: Vec::new(),
            max_packet_size: None,
            last_will: None,
            client_id: ByteStr::new(),
            username: None,
            password: None,
        }
    }
}

/// Connect acknowledgment
#[derive(Debug, PartialEq, Clone)]
/// Connect packet content
pub struct ConnectAck {
    /// enables a Client to establish whether the Client and Server have a consistent view
    /// about whether there is already stored Session state.
    pub session_present: bool,
    pub reason_code: ConnectAckReasonCode,

    pub session_expiry_interval_secs: Option<u32>,
    pub receive_max: Option<NonZeroU16>,
    pub max_qos: Option<QoS>,
    pub retain_available: Option<bool>,
    pub max_packet_size: Option<u32>,
    pub assigned_client_id: Option<ByteStr>,
    pub topic_alias_max: u16,
    pub reason_string: Option<ByteStr>,
    pub user_properties: UserProperties,
    pub wildcard_subscription_available: Option<bool>,
    pub subscription_identifiers_available: Option<bool>,
    pub shared_subscription_available: Option<bool>,
    pub server_keepalive_sec: Option<u16>,
    pub response_info: Option<ByteStr>,
    pub server_reference: Option<ByteStr>,
    pub auth_method: Option<ByteStr>,
    pub auth_data: Option<Bytes>,
}

impl Default for ConnectAck {
    fn default() -> Self {
        Self {
            session_present: false,
            reason_code: ConnectAckReasonCode::Success,
            session_expiry_interval_secs: None,
            receive_max: None,
            max_qos: None,
            retain_available: None,
            max_packet_size: None,
            assigned_client_id: None,
            topic_alias_max: 0,
            reason_string: None,
            user_properties: Vec::new(),
            wildcard_subscription_available: None,
            subscription_identifiers_available: None,
            shared_subscription_available: None,
            server_keepalive_sec: None,
            response_info: None,
            server_reference: None,
            auth_method: None,
            auth_data: None,
        }
    }
}

/// DISCONNECT message
#[derive(Debug, PartialEq, Clone)]
pub struct Disconnect {
    pub reason_code: DisconnectReasonCode,
    pub session_expiry_interval_secs: Option<u32>,
    pub server_reference: Option<ByteStr>,
    pub reason_string: Option<ByteStr>,
    pub user_properties: UserProperties,
}

impl Default for Disconnect {
    fn default() -> Self {
        Self {
            reason_code: DisconnectReasonCode::NormalDisconnection,
            session_expiry_interval_secs: None,
            server_reference: None,
            reason_string: None,
            user_properties: Vec::new(),
        }
    }
}

/// AUTH message
#[derive(Debug, PartialEq, Clone)]
pub struct Auth {
    pub reason_code: AuthReasonCode,
    pub auth_method: Option<ByteStr>,
    pub auth_data: Option<Bytes>,
    pub reason_string: Option<ByteStr>,
    pub user_properties: UserProperties,
}

impl Default for Auth {
    fn default() -> Self {
        Self {
            reason_code: AuthReasonCode::Success,
            auth_method: None,
            auth_data: None,
            reason_string: None,
            user_properties: Vec::new(),
        }
    }
}

/// PUBLISH message
#[derive(Debug, PartialEq, Clone)]
pub struct Publish {
    /// this might be re-delivery of an earlier attempt to send the Packet.
    pub dup: bool,
    pub retain: bool,
    /// the level of assurance for delivery of an Application Message.
    pub qos: QoS,
    /// only present in PUBLISH Packets where the QoS level is 1 or 2.
    pub packet_id: Option<NonZeroU16>,
    pub topic: ByteStr,
    pub payload: Bytes,

    pub properties: PublishProperties,
    // pub topic_alias: Option<NonZeroU16>,
    // pub correlation_data: Option<Bytes>,
    // pub message_expiry_interval: Option<NonZeroU32>,
    // pub content_type: Option<ByteStr>,
    // pub user_properties: UserProperties,
    // pub is_utf8_payload: Option<bool>,
    // pub response_topic: Option<ByteStr>,
    // pub subscription_ids: Option<Vec<NonZeroU32>>,
}

impl Default for Publish {
    fn default() -> Self {
        Self {
            dup: false,
            retain: false,
            qos: QoS::AtLeastOnce,
            packet_id: None,
            topic: ByteStr::default(),
            payload: Bytes::default(),

            properties: PublishProperties::default(),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct PublishProperties {
    pub topic_alias: Option<NonZeroU16>,
    pub correlation_data: Option<Bytes>,
    pub message_expiry_interval: Option<NonZeroU32>,
    pub content_type: Option<ByteStr>,
    pub user_properties: UserProperties,
    pub is_utf8_payload: Option<bool>,
    pub response_topic: Option<ByteStr>,
    pub subscription_ids: Option<Vec<NonZeroU32>>,
}

impl Default for PublishProperties {
    fn default() -> Self {
        Self {
            topic_alias: None,
            correlation_data: None,
            message_expiry_interval: None,
            content_type: None,
            user_properties: Vec::new(),
            is_utf8_payload: None,
            response_topic: None,
            subscription_ids: None,
        }
    }
}

/// PUBACK/PUBREC message content
#[derive(Debug, PartialEq, Clone)]
pub struct PublishAck {
    /// Packet Identifier
    pub packet_id: NonZeroU16,
    pub reason_code: PublishAckReasonCode,
    pub properties: AckProperties,
}

/// PUBREL/PUBCOMP message content
#[derive(Debug, PartialEq, Clone)]
pub struct PublishAck2 {
    /// Packet Identifier
    pub packet_id: NonZeroU16,
    pub reason_code: PublishAck2ReasonCode,
    pub properties: AckProperties,
}

/// *ACK message properties
#[derive(Debug, PartialEq, Clone)]
pub struct AckProperties {
    pub reason_string: Option<ByteStr>,
    pub user_properties: UserProperties,
}

impl Default for AckProperties {
    fn default() -> Self {
        AckProperties {
            reason_string: None,
            user_properties: UserProperties::default(),
        }
    }
}

// Represents SUBSCRIBE packet
#[derive(Debug, PartialEq, Clone)]
pub struct Subscribe {
    /// Packet Identifier
    pub packet_id: NonZeroU16,
    /// Subscription Identifier
    pub id: Option<NonZeroU32>,
    pub user_properties: UserProperties,
    /// the list of Topic Filters and QoS to which the Client wants to subscribe.
    pub topic_filters: Vec<(ByteStr, SubscriptionOptions)>,
}

#[derive(Debug, PartialEq, Clone)]
pub struct SubscriptionOptions {
    pub qos: QoS,
    pub no_local: bool,
    pub retain_as_published: bool,
    pub retain_handling: RetainHandling,
}

prim_enum! {
    pub enum RetainHandling {
        AtSubscribe = 0,
        AtSubscribeNew = 1,
        NoAtSubscribe = 2
    }
}

// Represents SUBACK packet
#[derive(Debug, PartialEq, Clone)]
pub struct SubscribeAck {
    pub packet_id: NonZeroU16,
    pub properties: AckProperties,
    /// corresponds to a Topic Filter in the SUBSCRIBE Packet being acknowledged.
    pub status: Vec<SubscribeAckReasonCode>,
}

/// Represents UNSUBSCRIBE packet
#[derive(Debug, PartialEq, Clone)]
pub struct Unsubscribe {
    /// Packet Identifier
    pub packet_id: NonZeroU16,
    pub user_properties: UserProperties,
    /// the list of Topic Filters that the Client wishes to unsubscribe from.
    pub topic_filters: Vec<ByteStr>,
}

/// Represents UNSUBACK packet
#[derive(Debug, PartialEq, Clone)]
pub struct UnsubscribeAck {
    /// Packet Identifier
    pub packet_id: NonZeroU16,
    pub properties: AckProperties,
    pub status: Vec<UnsubscribeAckReasonCode>,
}

#[derive(Debug, PartialEq, Clone)]
pub enum WillProperty {
    Utf8Payload(bool),
    MessageExpiryInterval(u32),
    ContentType(ByteStr),
    ResponseTopic(ByteStr),
    CorrelationData(Bytes),
    SubscriptionIdentifier(u32),
    WillDelayInterval(u32),
    User(ByteStr, ByteStr),
}

#[derive(Debug, PartialEq, Clone)]
/// MQTT Control Packets
pub enum Packet {
    /// Client request to connect to Server
    Connect(Connect),
    /// Connect acknowledgment
    ConnectAck(ConnectAck),
    /// Publish message
    Publish(Publish),
    /// Publish acknowledgment
    PublishAck(PublishAck),
    /// Publish received (assured delivery part 1)
    PublishReceived(PublishAck),
    /// Publish release (assured delivery part 2)
    PublishRelease(PublishAck2),
    /// Publish complete (assured delivery part 3)
    PublishComplete(PublishAck2),
    /// Client subscribe request
    Subscribe(Subscribe),
    /// Subscribe acknowledgment
    SubscribeAck(SubscribeAck),
    /// Unsubscribe request
    Unsubscribe(Unsubscribe),
    /// Unsubscribe acknowledgment
    UnsubscribeAck(UnsubscribeAck),
    /// PING request
    PingRequest,
    /// PING response
    PingResponse,
    /// Disconnection is advertised
    Disconnect(Disconnect),
    /// Auth exchange
    Auth(Auth),
}

pub(crate) mod packet_type {
    pub const CONNECT: u8 = 0b0001_0000;
    pub const CONNACK: u8 = 0b0010_0000;
    pub const PUBLISH_START: u8 = 0b0011_0000;
    pub const PUBLISH_END: u8 = 0b0011_1111;
    pub const PUBACK: u8 = 0b0100_0000;
    pub const PUBREC: u8 = 0b0101_0000;
    pub const PUBREL: u8 = 0b0110_0010;
    pub const PUBCOMP: u8 = 0b0111_0000;
    pub const SUBSCRIBE: u8 = 0b1000_0010;
    pub const SUBACK: u8 = 0b1001_0000;
    pub const UNSUBSCRIBE: u8 = 0b1010_0010;
    pub const UNSUBACK: u8 = 0b1011_0000;
    pub const PINGREQ: u8 = 0b1100_0000;
    pub const PINGRESP: u8 = 0b1101_0000;
    pub const DISCONNECT: u8 = 0b1110_0000;
    pub const AUTH: u8 = 0b1111_0000;
}

pub(crate) mod property_type {
    pub const UTF8_PAYLOAD: u8 = 0x01;
    pub const MSG_EXPIRY_INT: u8 = 0x02;
    pub const CONTENT_TYPE: u8 = 0x03;
    pub const RESP_TOPIC: u8 = 0x08;
    pub const CORR_DATA: u8 = 0x09;
    pub const SUB_ID: u8 = 0x0B;
    pub const SESS_EXPIRY_INT: u8 = 0x11;
    pub const ASSND_CLIENT_ID: u8 = 0x12;
    pub const SERVER_KA: u8 = 0x13;
    pub const AUTH_METHOD: u8 = 0x15;
    pub const AUTH_DATA: u8 = 0x16;
    pub const REQ_PROB_INFO: u8 = 0x17;
    pub const WILL_DELAY_INT: u8 = 0x18;
    pub const REQ_RESP_INFO: u8 = 0x19;
    pub const RESP_INFO: u8 = 0x1A;
    pub const SERVER_REF: u8 = 0x1C;
    pub const REASON_STRING: u8 = 0x1F;
    pub const RECEIVE_MAX: u8 = 0x21;
    pub const TOPIC_ALIAS_MAX: u8 = 0x22;
    pub const TOPIC_ALIAS: u8 = 0x23;
    pub const MAX_QOS: u8 = 0x24;
    pub const RETAIN_AVAIL: u8 = 0x25;
    pub const USER: u8 = 0x26;
    pub const MAX_PACKET_SIZE: u8 = 0x27;
    pub const WILDCARD_SUB_AVAIL: u8 = 0x28;
    pub const SUB_IDS_AVAIL: u8 = 0x29;
    pub const SHARED_SUB_AVAIL: u8 = 0x2A;
}

prim_enum! {
    /// CONNACK reason codes
    pub enum ConnectAckReasonCode {
        Success = 0,
        UnspecifiedError = 128,
        MalformedPacket = 129,
        ProtocolError = 130,
        ImplementationSpecificError = 131,
        UnsupportedProtocolVersion = 132,
        ClientIdentifierNotValid = 133,
        BadUserNameOrPassword = 134,
        NotAuthorized = 135,
        ServerUnavailable = 136,
        ServerBusy = 137,
        Banned = 138,
        BadAuthenticationMethod = 140,
        TopicNameInvalid = 144,
        PacketTooLarge = 149,
        QuotaExceeded = 151,
        PayloadFormatInvalid = 153,
        RetainNotSupported = 154,
        QosNotSupported = 155,
        UseAnotherServer = 156,
        ServerMoved = 157,
        ConnectionRateExceeded = 159
    }
}

impl ConnectAckReasonCode {
    pub fn reason(self) -> &'static str {
        match self {
            ConnectAckReasonCode::Success => "Connection Accepted",
            ConnectAckReasonCode::UnsupportedProtocolVersion => {
                "protocol version is not supported"
            }
            ConnectAckReasonCode::ClientIdentifierNotValid => "client identifier is invalid",
            ConnectAckReasonCode::ServerUnavailable => "Server unavailable",
            ConnectAckReasonCode::BadUserNameOrPassword => "bad user name or password",
            ConnectAckReasonCode::NotAuthorized => "not authorized",
            _ => "Connection Refused",
        }
    }
}

prim_enum! {
    /// DISCONNECT reason codes
    pub enum DisconnectReasonCode {
        NormalDisconnection = 0,
        DisconnectWithWillMessage = 4,
        UnspecifiedError = 128,
        MalformedPacket = 129,
        ProtocolError = 130,
        ImplementationSpecificError = 131,
        NotAuthorized = 135,
        ServerBusy = 137,
        ServerShuttingDown = 139,
        BadAuthenticationMethod = 140,
        KeepAliveTimeout = 141,
        SessionTakenOver = 142,
        TopicFilterInvalid = 143,
        TopicNameInvalid = 144,
        ReceiveMaximumExceeded = 147,
        TopicAliasInvalid = 148,
        PacketTooLarge = 149,
        MessageRateTooHigh = 150,
        QuotaExceeded = 151,
        AdministrativeAction = 152,
        PayloadFormatInvalid = 153,
        RetainNotSupported = 154,
        QosNotSupported = 155,
        UseAnotherServer = 156,
        ServerMoved = 157,
        SharedSubsriptionNotSupported = 158,
        ConnectionRateExceeded = 159,
        MaximumConnectTime = 160,
        SubscriptionIdentifiersNotSupported = 161,
        WildcardSubscriptionsNotSupported = 162
    }
}

prim_enum! {
    /// AUTH reason codes
    pub enum AuthReasonCode {
        Success = 0,
        ContinueAuth = 24,
        ReAuth = 25
    }
}

prim_enum! {
    /// SUBACK reason codes
    pub enum SubscribeAckReasonCode {
        GrantedQos0 = 0,
        GrantedQos1 = 1,
        GrantedQos2 = 2,
        UnspecifiedError = 128,
        ImplementationSpecificError = 131,
        NotAuthorized = 135,
        TopicFilterInvalid = 143,
        PacketIdentifierInUse = 145,
        QuotaExceeded = 151,
        SharedSubsriptionNotSupported = 158,
        SubscriptionIdentifiersNotSupported = 161,
        WildcardSubscriptionsNotSupported = 162
    }
}

prim_enum! {
    /// PUBACK / PUBREC reason codes
    pub enum PublishAckReasonCode {
        Success = 0,
        NoMatchingSubscribers = 16,
        UnspecifiedError = 128,
        ImplementationSpecificError = 131,
        NotAuthorized = 135,
        TopicNameInvalid = 144,
        PacketIdentifierInUse = 145,
        ReceiveMaximumExceeded = 147,
        QuotaExceeded = 151,
        PayloadFormatInvalid = 153
    }
}

prim_enum! {
    /// PUBREL / PUBCOMP reason codes
    pub enum PublishAck2ReasonCode {
        Success = 0,
        PacketIdNotFound = 146
    }
}

prim_enum! {
    /// UNSUBACK reason codes
    pub enum UnsubscribeAckReasonCode {
        Success = 0,
        NoSubscriptionExisted = 17,
        UnspecifiedError = 128,
        ImplementationSpecificError = 131,
        NotAuthorized = 135,
        TopicFilterInvalid = 143,
        PacketIdentifierInUse = 145
    }
}
