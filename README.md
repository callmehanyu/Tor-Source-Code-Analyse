Tor版本：0.4.2.5

----------

PS:stream=stream conn=stream connection=ap connection=entry connection

----------

在Tor协议中，电路（circuit）建立的代价是比较高的，所以一条电路允许被多个流（stream）复用。我们来看下流是如何选择一条合适的电路的。
# 1 数据结构
我们这里主要关注与流、电路相关的数据结构。
## 1.1 connection相关
### 1.1.1 /src/core/mainloop/connection.c
The module implements the abstract type,`connection_t`在`connection_st.h`中定义（见**1.1.2**节），The subtypes are:
- `listener_connection_t`, implemented here in connection.c
- `dir_connection_t`, implemented in directory.c
- `or_connection_t`, implemented in connection_or.c
- `edge_connection_t`, 在`edge_connection_st.h`中定义（见**1.1.3**节），implemented in connection_edge.h, along with its subtype(s):
	- `entry_connection_t`, 在`entry_connection_st.h`中定义（见**1.1.4**节），also implemented in connection_edge.c
- `control_connection_t`, implemented in control.c

### 1.1.2 /src/core/or/connection_st.h
connection分为OR connection，exit connection和**AP connection**三种类型，每一个connection都有时刻变化的状态和输入输出缓冲区。我们主要关注部分如下属性：
```c
uint8_t state; /**< Current state of this connection. */
unsigned int type:5; /**< What kind of connection is this? */
unsigned int purpose:5; /**< Only used for DIR and EXIT types currently. */
？unsigned int linked:1; /**< True if there is, or has been, a linked_conn. */
？unsigned int proxy_state:4;/** CONNECT/SOCKS proxy client handshake state (for outgoing connections). */
uint64_t global_identifier;/** Unique identifier for this connection on this Tor instance. */
？int socket_family; /**< Address family of this connection's socket.  Usually AF_INET, but it can also be AF_UNIX, or AF_INET6 */
？tor_addr_t addr; /**< IP that socket "s" is directly connected to; may be the IP address for a proxy or pluggable transport,see "address" for the address of the final destination.*/
？uint16_t port; /**< If non-zero, port that socket "s" is directly connected to;may be the port for a proxy or pluggable transport,see "address" for the port at the final destination. */
？char *address; /**< FQDN (or IP) and port of the final destination for this connection; this is always the remote address, it is passed to a proxy or pluggable transport if one in use.See "addr" and "port" for the address that socket "s" is directly connected to.strdup into this, because free_connection() frees it. */
```
### 1.1.3 /src/core/or/edge_connection_st.h
edge connection 分为entry (ap，stream) connection 和 exit connection.
```c
connection_t base_;
struct edge_connection_t *next_stream; /**< Points to the next stream at this edge, if any */
int package_window; /**< How many more relay cells can I send into the circuit? */
int deliver_window; /**< How many more relay cells can end at me? */
struct circuit_t *on_circuit; /**< The circuit (if any) that this edge connection is using. */
?struct crypt_path_t *cpath_layer;/** A pointer to which node in the circ this conn exits at.  Set for AP connections and for hidden service exit connections. */
rend_data_t *rend_data;  /** What rendezvous service are we querying for (if an AP) or providing (if an exit)? */
struct hs_ident_edge_conn_t *hs_ident;/* Hidden service connection identifier for edge connections. Used by the HS client-side code to identify client SOCKS connections and by the service-side code to match HS circuits with their streams. */
streamid_t stream_id; /**< The stream ID used for this edge connection on its circuit */
uint16_t end_reason;/** The reason why this connection is closing; passed to the controller. */
unsigned int is_dns_request:1;/** True iff this connection is for a DNS request only. */
unsigned int is_reverse_dns_lookup:1;/** True iff this connection is for a PTR DNS request. (exit only) */
uint64_t dirreq_id;/** Unique ID for directory requests; this used to be in connection_t, but that's going away and being used on channels instead.  We still tag edge connections with dirreq_id from circuits, so it's copied here. */
```
### 1.1.4 /src/core/or/entry_connection_st.h
entry connection 分为 SOCKS connection、 DNS request、 TransPort connection 、 NATD connection
```c
struct edge_connection_t edge_;

  /** Nickname of planned exit node -- used with .exit support. */
  /* XXX prop220: we need to make chosen_exit_name able to encode Ed IDs too.
   * That's logically part of the UI parts for prop220 though. */
char *chosen_exit_name;

socks_request_t *socks_request; /**< SOCKS structure describing request (AP
                                   * only.) */

  /* === Isolation related, AP only. === */
entry_port_cfg_t entry_cfg;
  /** AP only: The newnym epoch in which we created this connection. */
unsigned nym_epoch;

  /** AP only: The original requested address before we rewrote it. */
char *original_dest_address;
  /* Other fields to isolate on already exist.  The ClientAddr is addr.  The
     ClientProtocol is a combination of type and socks_request->
     socks_version.  SocksAuth is socks_request->username/password.
     DestAddr is in socks_request->address. */

  /** Number of times we've reassigned this application connection to
   * a new circuit. We keep track because the timeout is longer if we've
   * already retried several times. */
uint8_t num_socks_retries;

#define NUM_CIRCUITS_LAUNCHED_THRESHOLD 10
  /** Number of times we've launched a circuit to handle this stream. If
    * it gets too high, that could indicate an inconsistency between our
    * "launch a circuit to handle this stream" logic and our "attach our
    * stream to one of the available circuits" logic. */
unsigned int num_circuits_launched:4;

  /** True iff this stream must attach to a one-hop circuit (e.g. for
   * begin_dir). */
unsigned int want_onehop:1;
  /** True iff this stream should use a BEGIN_DIR relay command to establish
   * itself rather than BEGIN (either via onehop or via a whole circuit). */
unsigned int use_begindir:1;

  /** For AP connections only. If 1, and we fail to reach the chosen exit,
   * stop requiring it. */
unsigned int chosen_exit_optional:1;
  /** For AP connections only. If non-zero, this exit node was picked as
   * a result of the TrackHostExit, and the value decrements every time
   * we fail to complete a circuit to our chosen exit -- if it reaches
   * zero, abandon the associated mapaddress. */
unsigned int chosen_exit_retries:3;

  /** True iff this is an AP connection that came from a transparent or
   * NATd connection */
unsigned int is_transparent_ap:1;

  /** For AP connections only: Set if this connection's target exit node
   * allows optimistic data (that is, data sent on this stream before
   * the exit has sent a CONNECTED cell) and we have chosen to use it.
   */
unsigned int may_use_optimistic_data : 1;
```
## 1.2 circuit 相关
### 1.2.1src\core\or\circuit_st.h
circuit是洋葱路由网络上的路径。Applications可以连接到circuit的一端，并可以在circuit的另一端创建exit connections。 AP和exit connections只有一个与之关联的circuit（因此，当circuit关闭时，这些连接类型也会关闭），而OR connections可一次多路复用多个circuit，即使没有circuit在OR connections上面运行，它们也不会关闭。circuit_t 有两个子类：`origin_circuit_t`和`or_circuit_t`
```c
  /** The channel that is next in this circuit. */
channel_t *n_chan;

  /**
   * The circuit_id used in the next (forward) hop of this circuit;
   * this is unique to n_chan, but this ordered pair is globally
   * unique:
   *
   * (n_chan->global_identifier, n_circ_id)
   */
 circid_t n_circ_id;
  /** Queue of cells waiting to be transmitted on n_chan */
  cell_queue_t n_chan_cells;

  /**
   * The hop to which we want to extend this circuit.  Should be NULL if
   * the circuit has attached to a channel.
   */
  extend_info_t *n_hop;

  /** True iff we are waiting for n_chan_cells to become less full before
   * allowing p_streams to add any more cells. (Origin circuit only.) */
  unsigned int streams_blocked_on_n_chan : 1;
  /** True iff we are waiting for p_chan_cells to become less full before
   * allowing n_streams to add any more cells. (OR circuit only.) */
  unsigned int streams_blocked_on_p_chan : 1;
  /** True iff this circuit has received a DESTROY cell in either direction */
  unsigned int received_destroy : 1;

  /** True iff we have sent a sufficiently random data cell since last
   * we reset send_randomness_after_n_cells. */
  unsigned int have_sent_sufficiently_random_cell : 1;

  uint8_t state; /**< Current status of this circuit. */
  uint8_t purpose; /**< Why are we creating this circuit? */
/** How many relay data cells can we package (read from edge streams)
   * on this circuit before we receive a circuit-level sendme cell asking
   * for more? */
  int package_window;
  /** How many relay data cells will we deliver (write to edge streams)
   * on this circuit? When deliver_window gets low, we send some
   * circuit-level sendme cells to indicate that we're willing to accept
   * more. */
  int deliver_window;
  /**
   * How many cells do we have until we need to send one that contains
   * sufficient randomness?  Used to ensure that authenticated SENDME cells
   * will reflect some unpredictable information.
   **/
  uint16_t send_randomness_after_n_cells;
  /** Temporary field used during circuits_handle_oom. */
  uint32_t age_tmp;

  /** For storage while n_chan is pending (state CIRCUIT_STATE_CHAN_WAIT). */
  struct create_cell_t *n_chan_create_cell;

  /** When did circuit construction actually begin (ie send the
   * CREATE cell or begin cannibalization).
   *
   * Note: This timer will get reset if we decide to cannibalize
   * a circuit. It may also get reset during certain phases of hidden
   * service circuit use.
   *
   * We keep this timestamp with a higher resolution than most so that the
   * circuit-build-time tracking code can get millisecond resolution.
   */
  struct timeval timestamp_began;

  /** This timestamp marks when the init_circuit_base constructor ran. */
  struct timeval timestamp_created;

  /** When the circuit was first used, or 0 if the circuit is clean.
   *
   * XXXX Note that some code will artificially adjust this value backward
   * in time in order to indicate that a circuit shouldn't be used for new
   * streams, but that it can stay alive as long as it has streams on it.
   * That's a kludge we should fix.
   *
   * XXX The CBT code uses this field to record when HS-related
   * circuits entered certain states.  This usage probably won't
   * interfere with this field's primary purpose, but we should
   * document it more thoroughly to make sure of that.
   *
   * XXX The SocksPort option KeepaliveIsolateSOCKSAuth will artificially
   * adjust this value forward each time a suitable stream is attached to an
   * already constructed circuit, potentially keeping the circuit alive
   * indefinitely.
   */
  time_t timestamp_dirty;

  uint16_t marked_for_close; /**< Should we close this circuit at the end of
                              * the main loop? (If true, holds the line number
                              * where this circuit was marked.) */
  const char *marked_for_close_file; /**< For debugging: in which file was this
                                      * circuit marked for close? */
  /** For what reason (See END_CIRC_REASON...) is this circuit being closed?
   * This field is set in circuit_mark_for_close and used later in
   * circuit_about_to_free. */
  int marked_for_close_reason;
  /** As marked_for_close_reason, but reflects the underlying reason for
   * closing this circuit.
   */
  int marked_for_close_orig_reason;

  /** Unique ID for measuring tunneled network status requests. */
  uint64_t dirreq_id;
  /** If set, points to an HS token that this circuit might be carrying.
   *  Used by the HS circuitmap.  */
  struct hs_token_t *hs_token;
  /** Hashtable node: used to look up the circuit by its HS token using the HS
      circuitmap. */
  HT_ENTRY(circuit_t) hs_circuitmap_node;

  /** Adaptive Padding state machines: these are immutable. The state machines
   *  that come from the consensus are saved to a global structure, to avoid
   *  per-circuit allocations. This merely points to the global copy in
   *  origin_padding_machines or relay_padding_machines that should never
   *  change or get deallocated.
   *
   *  Each element of this array corresponds to a different padding machine,
   *  and we can have up to CIRCPAD_MAX_MACHINES such machines. */
  const struct circpad_machine_spec_t *padding_machine[CIRCPAD_MAX_MACHINES];
```
### 1.2.2 \src\core\or\origin_circuit_st.h
用于circuit的build（/src/core/or/circuitbuild.c）与use（/src/core/or/circuituse.c）。保留cipher keys和状态，以便沿着给定的circuit发送数据。在OP处，它具有一系列密码，每个密码与circuit上的单个OR共享。单独的密码用于“向前”（远离OP）和“向后”（朝OP）数据。在OR处，circuit只有两个stream cipher：一个用于数据前进，而另一个用于数据后退。
```c
circuit_t base_;

  /** Linked list of AP streams (or EXIT streams if hidden service) associated with this circuit. */
edge_connection_t *p_streams;

  /** Smartlist of half-closed streams (half_edge_t*) that still have pending activity */
smartlist_t *half_streams;

  /** Build state for this circuit. It includes the intended path
   * length, the chosen exit router, rendezvous information, etc.
   */
  cpath_build_state_t *build_state;
  /** The doubly-linked list of crypt_path_t entries, one per hop,
   * for this circuit. This includes ciphers for each hop,
   * integrity-checking digests for each hop, and package/delivery
   * windows for each hop.
   */
  crypt_path_t *cpath;

  /** Holds all rendezvous data on either client or service side. */
  rend_data_t *rend_data;

  /** Holds hidden service identifier on either client or service side. This
   * is for both introduction and rendezvous circuit. */
  struct hs_ident_circuit_t *hs_ident;

  /** Holds the data that the entry guard system uses to track the
   * status of the guard this circuit is using, and thereby to determine
   * whether this circuit can be used. */
  struct circuit_guard_state_t *guard_state;

  /** How many more relay_early cells can we send on this circuit, according
   * to the specification? */
  unsigned int remaining_relay_early_cells : 4;

  /** Set if this circuit is insanely old and we already informed the user */
  unsigned int is_ancient : 1;

  /** Set if this circuit has already been opened. Used to detect
   * cannibalized circuits. */
  unsigned int has_opened : 1;

  /**
   * Path bias state machine. Used to ensure integrity of our
   * circuit building and usage accounting. See path_state_t
   * for more details.
   */
  path_state_bitfield_t path_state : 3;

  /* If this flag is set, we should not consider attaching any more
   * connections to this circuit. */
  unsigned int unusable_for_new_conns : 1;

  /* If this flag is set (due to padding negotiation failure), we should
   * not try to negotiate further circuit padding. */
  unsigned padding_negotiation_failed : 1;

  /**
   * Tristate variable to guard against pathbias miscounting
   * due to circuit purpose transitions changing the decision
   * of pathbias_should_count(). This variable is informational
   * only. The current results of pathbias_should_count() are
   * the official decision for pathbias accounting.
   */
  uint8_t pathbias_shouldcount;
#define PATHBIAS_SHOULDCOUNT_UNDECIDED 0
#define PATHBIAS_SHOULDCOUNT_IGNORED   1
#define PATHBIAS_SHOULDCOUNT_COUNTED   2

  /** For path probing. Store the temporary probe stream ID
   * for response comparison */
  streamid_t pathbias_probe_id;

  /** For path probing. Store the temporary probe address nonce
   * (in host byte order) for response comparison. */
  uint32_t pathbias_probe_nonce;

  /** Set iff this is a hidden-service circuit which has timed out
   * according to our current circuit-build timeout, but which has
   * been kept around because it might still succeed in connecting to
   * its destination, and which is not a fully-connected rendezvous
   * circuit.
   *
   * (We clear this flag for client-side rendezvous circuits when they
   * are 'joined' to the other side's rendezvous circuit, so that
   * connection_ap_handshake_attach_circuit can put client streams on
   * the circuit.  We also clear this flag for service-side rendezvous
   * circuits when they are 'joined' to a client's rend circ, but only
   * for symmetry with the client case.  Client-side introduction
   * circuits are closed when we get a joined rend circ, and
   * service-side introduction circuits never have this flag set.) */
  unsigned int hs_circ_has_timed_out : 1;

  /** Set iff this circuit has been given a relaxed timeout because
   * no circuits have opened. Used to prevent spamming logs. */
  unsigned int relaxed_timeout : 1;

  /** Set iff this is a service-side rendezvous circuit for which a
   * new connection attempt has been launched.  We consider launching
   * a new service-side rend circ to a client when the previous one
   * fails; now that we don't necessarily close a service-side rend
   * circ when we launch a new one to the same client, this flag keeps
   * us from launching two retries for the same failed rend circ. */
  unsigned int hs_service_side_rend_circ_has_been_relaunched : 1;

  /** What commands were sent over this circuit that decremented the
   * RELAY_EARLY counter? This is for debugging task 878. */
  uint8_t relay_early_commands[MAX_RELAY_EARLY_CELLS_PER_CIRCUIT];

  /** How many RELAY_EARLY cells have been sent over this circuit? This is
   * for debugging task 878, too. */
  int relay_early_cells_sent;

  /** The next stream_id that will be tried when we're attempting to
   * construct a new AP stream originating at this circuit. */
  streamid_t next_stream_id;

  /** True if we have associated one stream to this circuit, thereby setting
   * the isolation parameters for this circuit.  Note that this doesn't
   * necessarily mean that we've <em>attached</em> any streams to the circuit:
   * we may only have marked up this circuit during the launch process.
   */
  unsigned int isolation_values_set : 1;
  /** True iff any stream has <em>ever</em> been attached to this circuit.
   *
   * In a better world we could use timestamp_dirty for this, but
   * timestamp_dirty is far too overloaded at the moment.
   */
  unsigned int isolation_any_streams_attached : 1;

  /** A bitfield of ISO_* flags for every isolation field such that this
   * circuit has had streams with more than one value for that field
   * attached to it. */
  uint8_t isolation_flags_mixed;

  /** @name Isolation parameters
   *
   * If any streams have been associated with this circ (isolation_values_set
   * == 1), and all streams associated with the circuit have had the same
   * value for some field ((isolation_flags_mixed & ISO_FOO) == 0), then these
   * elements hold the value for that field.
   *
   * Note again that "associated" is not the same as "attached": we
   * preliminarily associate streams with a circuit while the circuit is being
   * launched, so that we can tell whether we need to launch more circuits.
   *
   * @{
   */
  uint8_t client_proto_type;
  uint8_t client_proto_socksver;
  uint16_t dest_port;
  tor_addr_t client_addr;
  char *dest_address;
  int session_group;
  unsigned nym_epoch;
  size_t socks_username_len;
  uint8_t socks_password_len;
  /* Note that the next two values are NOT NUL-terminated; see
     socks_username_len and socks_password_len for their lengths. */
  char *socks_username;
  char *socks_password;
  /** Global identifier for the first stream attached here; used by
   * ISO_STREAM. */
  uint64_t associated_isolated_stream_global_id;
  /**@}*/
  /** A list of addr_policy_t for this circuit in particular. Used by
   * adjust_exit_policy_from_exitpolicy_failure.
   */
  smartlist_t *prepend_policy;

  /** How long do we wait before closing this circuit if it remains
   * completely idle after it was built, in seconds? This value
   * is randomized on a per-circuit basis from CircuitsAvailableTimoeut
   * to 2*CircuitsAvailableTimoeut. */
  int circuit_idle_timeout;
```

### 1.2.3 /src/core/or/cpath_build_state_st.h
Information used to build a circuit.
```c
  /** Intended length of the final circuit. */
int desired_path_len;
  /** How to extend to the planned exit node. */
extend_info_t *chosen_exit;
  /** Whether every node in the circ must have adequate uptime. */
unsigned int need_uptime : 1;
  /** Whether every node in the circ must have adequate capacity. */
unsigned int need_capacity : 1;
  /** Whether the last hop was picked with exiting in mind. */
unsigned int is_internal : 1;
  /** Did we pick this as a one-hop tunnel (not safe for other streams)?
   * These are for encrypted dir conns that exit to this router, not
   * for arbitrary exits from the circuit. */
unsigned int onehop_tunnel : 1;
  /** The crypt_path_t to append after rendezvous: used for rendezvous. */
crypt_path_t *pending_final_cpath;
  /** A ref-counted reference to the crypt_path_t to append after
   * rendezvous; used on the service side. */
crypt_path_reference_t *service_pending_final_cpath_ref;
  /** How many times has building a circuit for this task failed? */
int failure_count;
  /** At what time should we give up on this task? */
time_t expiry_time;
```
### 1.2.4 \src\core\or\or_circuit_st.h
用于将两个connection链接在一起：edge connection和OR connection，或两个OR connection。（加入OR connection时，circuit_t仅影响发送到该connection上特定circID的cell。加入edge connection时，circuit_t影响所有数据）
# 2 stream选择circuit算法
![](https://i.imgur.com/tF7ov5m.jpg)
## 2.1 connection_ap_attach_pending(int retry)
列出的所有等待新circuit重试的AP stream。 如果stream有可用circuit，请attach circuit。 否则，启动新circuit。 如果重试失败，则仅检查列表是否包含至少一个我们尚未尝试附加到circuit的stream。
## 2.2 connection_ap_handshake_attach_circuit(entry_connection_t *conn)
Try to find a **safe live** circuit for stream conn.
If we find one,  attach the stream, send appropriate cells, and return 1.  
Otherwise,  try to launch new circuit(s) for the stream.  If we can launch  circuits, return 0.  
Otherwise, if we simply can't proceed with  this stream, return -1. 
![](https://i.imgur.com/6rEX7JH.jpg)
## 2.3 circuit_get_open_circ_or_launch(entry_connection_t *conn,uint8_t desired_circuit_purpose,origin_circuit_t **circp)
Find an open circ that we're **happy** to use for conn and return 1.(这个happy看的我一愣一愣的) 
If there isn't one, and there isn't one on the way, launch one and return 0. 
If it will never work, return -1.
Write the found(open) or in-progress(on the way) or launched circ into *circp.
![](https://i.imgur.com/pEFDJI8.jpg)
## 2.4 circuit_get_best(const entry_connection_t *conn,int must_be_open, uint8_t purpose,int need_uptime, int need_internal)
找到conn可以使用的最佳circuit，最好是脏的circuit。 circuit不能太老。
Conn必须被定义。
If must_be_open，请忽略不在CIRCUIT_STATE_OPEN中的circuit。 
circ_purpose指定我们必须具有哪种circuit，它可以是C_GENERAL，C_INTRODUCE_ACK_WAIT或C_REND_JOINED。如果它是REND_JOINED且must_be_open == 0，则返回您可以找到的the closest rendezvous-purposed circuit。
如果它是INTRODUCE_ACK_WAIT并且must_be_open == 0，则返回您可以找到的最接近的引入专用circuit。
![](https://i.imgur.com/5B1FLNN.jpg)
## 2.5 circuit_is_acceptable(const origin_circuit_t *origin_circ,const entry_connection_t *conn,int must_be_open, uint8_t purpose,int need_uptime, int need_internal,time_t now)
去除那些不适合附加到stream的circuits，以便于circuit_is_better在剩下的circuits集合中选择一个最优的circuit。
![](https://i.imgur.com/RMPfBny.jpg)
## 2.6 circuit_is_better(const origin_circuit_t *oa, const origin_circuit_t *ob,const entry_connection_t *conn)
对circuit oa和ob进行比较
![](https://i.imgur.com/qRRw5ZB.jpg)
