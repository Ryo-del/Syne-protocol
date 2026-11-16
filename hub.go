package protocol

import lpprotocol "github.com/libp2p/go-libp2p/core/protocol"

// HubStreamProtocol — libp2p-протокол реестра Syne Key Hub на Syne Server (для Study).
// Mobile ходит за тем же через HTTPS облака (зеркало), см. Syne Cloud /api/v1/hub.
// Сами структуры запросов и записей — в пакете hub.
const HubStreamProtocol = lpprotocol.ID("/syne/hub/1.0.0")
