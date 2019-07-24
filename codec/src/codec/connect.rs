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

impl Parse for Connect {

}

impl EncodeLtd for Connect {
    
}