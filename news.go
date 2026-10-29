package protocol

import lpprotocol "github.com/libp2p/go-libp2p/core/protocol"

// News — школьные новости, которые администратор публикует на сервере.
// Клиент открывает поток, шлёт NewsRequest (framed JSON) и получает NewsResponse.
// Список отдаётся без картинок; картинку конкретного поста клиент запрашивает
// отдельно (NewsOpImage), чтобы лента грузилась быстро.
const NewsStreamProtocol = lpprotocol.ID("/syne/news/1.0.0")

// Картинка поста ограничена на сервере; кадр с запасом под JSON/base64.
const (
	NewsMaxImageBytes        = 5 * 1024 * 1024
	NewsMaxFrame      uint32 = 8 * 1024 * 1024
)

const (
	NewsOpList  = "news_list"
	NewsOpImage = "news_image"
)

const NewsTypeResponse = "news_response"

type NewsRequest struct {
	Type      string `json:"type"`
	SessionID string `json:"session_id"`
	PostID    int64  `json:"post_id,omitempty"` // news_image
	Limit     int    `json:"limit,omitempty"`   // news_list
}

type NewsPost struct {
	ID        int64  `json:"id"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	HasImage  bool   `json:"has_image"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

type NewsResponse struct {
	Type      string     `json:"type"`
	OK        bool       `json:"ok"`
	Error     string     `json:"error,omitempty"`
	Posts     []NewsPost `json:"posts,omitempty"`
	Image     []byte     `json:"image,omitempty"`
	ImageMime string     `json:"image_mime,omitempty"`
}
