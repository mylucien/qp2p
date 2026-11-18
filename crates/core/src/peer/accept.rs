//! 端点入站连接的**唯一**消费者。
//!
//! 以前每个打洞任务各自 `endpoint.accept()`：拨号方的 drain 任务、若干个
//! `answer_punch` 的监听任务同时在抢同一个端点。quinn 的 `accept()` 是
//! 多消费者竞争——每条 Incoming 只会交给其中一个轮询者。于是给 A 用的
//! 监听任务可能拿到本该属于 B 的连接并把它关掉，B 只看到"握手失败"或
//! "认证超时"，进而把候选判成"身份不对"。
//!
//! 这里把 accept 收敛成一条常驻循环：按来源 IP 把 Incoming 投递给注册过
//! 这个 IP 的订阅者，没人认领就 `refuse`（这正好是原来 drain 任务的作用，
//! 但不会再抢别人的连接）。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use quinn::{Endpoint, Incoming};
use tokio::sync::mpsc;

/// 单个订阅者的排队上限。打洞窗口里同一来源不会有这么多并发握手，
/// 满了说明对面在刷，直接拒掉比排队更合适。
const QUEUE: usize = 8;

/// 端点的入站分发中心。
pub struct AcceptHub {
    routes: Mutex<HashMap<IpAddr, mpsc::Sender<Incoming>>>,
}

impl AcceptHub {
    /// 起一条常驻 accept 循环。`Endpoint` 被关闭（renew / shutdown）后循环自然退出。
    pub fn spawn(endpoint: Endpoint) -> (Arc<Self>, tokio::task::JoinHandle<()>) {
        let hub = Arc::new(Self {
            routes: Mutex::new(HashMap::new()),
        });
        let task = tokio::spawn({
            let hub = hub.clone();
            async move {
                while let Some(incoming) = endpoint.accept().await {
                    let remote = incoming.remote_address();
                    // 锁只在取 sender 这一瞬间持有，后面 await 之前就放掉了
                    let sender = match hub.routes.lock() {
                        Ok(routes) => routes.get(&remote.ip()).cloned(),
                        Err(_) => None,
                    };
                    let Some(tx) = sender else {
                        tracing::trace!("[punch] 拒绝未知来源 {remote}");
                        incoming.refuse();
                        continue;
                    };
                    if let Err(e) = tx.try_send(incoming) {
                        // 订阅方已经走了，或者来不及收：拒掉，并清掉失效路由
                        tracing::trace!("[punch] 丢弃来自 {remote} 的连接: {e}");
                        match e {
                            mpsc::error::TrySendError::Full(i) => i.refuse(),
                            mpsc::error::TrySendError::Closed(i) => i.refuse(),
                        }
                        if let Ok(mut routes) = hub.routes.lock() {
                            routes.remove(&remote.ip());
                        }
                    }
                }
            }
        });
        (hub, task)
    }

    /// 订阅来自这些 IP 的入站连接。
    ///
    /// 同一个 IP 上的旧订阅会被顶掉——这是刻意的：同一时刻只该有一个
    /// 监听任务在等某个对端，重复订阅说明上层的去重没生效。
    pub fn subscribe(self: &Arc<Self>, ips: Vec<IpAddr>) -> Subscription {
        let (tx, rx) = mpsc::channel(QUEUE);
        if let Ok(mut routes) = self.routes.lock() {
            for ip in &ips {
                routes.insert(*ip, tx.clone());
            }
        }
        Subscription {
            hub: self.clone(),
            ips,
            tx,
            rx,
        }
    }
}

/// 一段订阅。Drop 时把路由摘掉，避免打洞结束后还往死通道里投递。
pub struct Subscription {
    hub: Arc<AcceptHub>,
    ips: Vec<IpAddr>,
    tx: mpsc::Sender<Incoming>,
    rx: mpsc::Receiver<Incoming>,
}

impl Subscription {
    pub async fn recv(&mut self) -> Option<Incoming> {
        self.rx.recv().await
    }
}

impl Drop for Subscription {
    fn drop(&mut self) {
        let Ok(mut routes) = self.hub.routes.lock() else {
            return;
        };
        for ip in &self.ips {
            // 只摘自己的：同一 IP 可能已经被后来者接管
            let mine = routes
                .get(ip)
                .map(|tx| tx.same_channel(&self.tx))
                .unwrap_or(false);
            if mine {
                routes.remove(ip);
            }
        }
    }
}
