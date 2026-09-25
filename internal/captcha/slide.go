package captcha

import (
	"embed"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io/fs"
	"strings"
	"sync"

	"github.com/wenlng/go-captcha/v2/base/option"
	"github.com/wenlng/go-captcha/v2/slide"
)

const (
	ImageWidth  = 300
	ImageHeight = 160
	TileSize    = 64
)

//go:embed assets/*.png
var assets embed.FS

var engine struct {
	once sync.Once
	capt slide.Captcha
	err  error
}

// Challenge contains renderable data and server-only target coordinates.
// Callers must never include TargetX/TargetY in a client response.
type Challenge struct {
	Image, Thumb     string
	ThumbX, ThumbY   int
	TargetX, TargetY int
}

func readImage(path string) (image.Image, error) {
	f, err := assets.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return png.Decode(f)
}

func initEngine() {
	paths, err := fs.Glob(assets, "assets/background-*.png")
	if err != nil {
		engine.err = fmt.Errorf("captcha backgrounds unavailable: %w", err)
		return
	}
	if len(paths) == 0 {
		engine.err = errors.New("captcha backgrounds unavailable")
		return
	}
	backgrounds := make([]image.Image, 0, len(paths))
	for _, path := range paths {
		img, err := readImage(path)
		if err != nil {
			engine.err = fmt.Errorf("decode %s: %w", path, err)
			return
		}
		backgrounds = append(backgrounds, img)
	}
	graphs := make([]image.Image, 0, 3)
	for _, name := range []string{"tile-overlay", "tile-shadow", "tile-mask"} {
		img, err := readImage("assets/" + name + ".png")
		if err != nil {
			engine.err = fmt.Errorf("decode %s: %w", name, err)
			return
		}
		graphs = append(graphs, img)
	}
	builder := slide.NewBuilder(
		slide.WithImageSize(option.Size{Width: ImageWidth, Height: ImageHeight}),
		slide.WithRangeGraphSize(option.RangeVal{Min: TileSize, Max: TileSize}),
	)
	builder.SetResources(
		slide.WithBackgrounds(backgrounds),
		slide.WithGraphImages([]*slide.GraphImage{{
			OverlayImage: graphs[0], ShadowImage: graphs[1], MaskImage: graphs[2],
		}}),
	)
	engine.capt = builder.Make()
}

// GenerateSlide creates a fresh puzzle from assets embedded in the Go binary.
func GenerateSlide() (Challenge, error) {
	engine.once.Do(initEngine)
	if engine.err != nil {
		return Challenge{}, engine.err
	}
	data, err := engine.capt.Generate()
	if err != nil {
		return Challenge{}, err
	}
	block := data.GetData()
	if block == nil {
		return Challenge{}, fmt.Errorf("captcha generator returned no target")
	}
	background, err := data.GetMasterImage().ToBase64()
	if err != nil {
		return Challenge{}, err
	}
	tile, err := data.GetTileImage().ToBase64()
	if err != nil {
		return Challenge{}, err
	}
	if !strings.HasPrefix(background, "data:image/jpeg;base64,") || !strings.HasPrefix(tile, "data:image/png;base64,") {
		return Challenge{}, fmt.Errorf("captcha generator returned unsupported image format")
	}
	return Challenge{Image: background, Thumb: tile,
		ThumbX: block.DX, ThumbY: block.DY,
		TargetX: block.X, TargetY: block.Y}, nil
}
