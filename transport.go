/**
* @Author: kiosk
* @Mail: weijiaxiang007@foxmail.com
* @Date: 2021/1/22
**/
package webtransport

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/logging"
	"github.com/lucas-clemente/quic-go/qlog"
	"io"
	"net/url"
	"os"
	"quic-web-transport/utils"
)

const (
	// https://tools.ietf.org/html/draft-vvv-webtransport-quic-02#section-3.1
	alpnQuicTransport = "wq-vvv-01"

	// https://tools.ietf.org/html/draft-vvv-webtransport-quic-02#section-3.2
	maxClientIndicationLength = 65535
)

type clientIndicationKey int16

const (
	clientIndicationKeyOrigin clientIndicationKey = 0
	clientIndicationKeyPath                       = 1
)

// ClientIndication, see https://tools.ietf.org/html/draft-vvv-webtransport-quic-02#section-3.2
type ClientIndication struct {
	// Origin indication value.
	Origin string
	// Path indication value.
	Path string
}

// Config for WebTransportServerQuic.
type Config struct {
	// ListenAddr sets an address to bind server to.
	ListenAddr string
	// TLSCertPath defines a path to .crt cert file.
	TLSCertPath string
	// TLSKeyPath defines a path to .key cert file
	TLSKeyPath string
	// AllowedOrigins represents list of allowed origins to connect from.
	AllowedOrigins []string
}

// WebTransportServerQuic can handle WebTransport QUIC connections.
// This example only shows bidirectional streams in action. Unidirectional
// stream communication is also possible but not implemented here. For unreliable
// communication with UDP datagram mentioned in
// https://tools.ietf.org/html/draft-vvv-webtransport-quic-02#section-5
// quic-go should implement https://tools.ietf.org/html/draft-ietf-quic-datagram-00
// draft (there is an ongoing pull request – see https://github.com/lucas-clemente/quic-go/pull/2162).
type WebTransportServerQuic struct {
	config Config
}

// NewWebTransportServerQuic creates new WebTransportServerQuic.
func NewWebTransportServerQuic(config Config) *WebTransportServerQuic {
	return &WebTransportServerQuic{
		config: config,
	}
}

// Run server.
func (s *WebTransportServerQuic) Run() error {
	listener, err := quic.ListenAddr(s.config.ListenAddr, s.generateTLSConfig(), s.generateQuicConfig())
	if err != nil {
		return err
	}
	utils.Logging.Info().Msg("Web Transport Server v0.1 Start ...")
	utils.Logging.Info().Msgf("Listening for %s connections on %s",listener.Addr().Network(),listener.Addr().String())

	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}
		utils.Logging.Info().Msgf("session accepted: %s", sess.RemoteAddr().String())

		go func() {
			defer func() {
				_ = sess.CloseWithError(0, "bye")
				utils.Logging.Info().Msgf("close session: %s", sess.RemoteAddr().String())
			}()
			s.handleSession(sess)
		}()
	}
}

func (s *WebTransportServerQuic) handleSession(sess quic.Session) {
	stream, err := sess.AcceptUniStream(context.Background())
	if err != nil {
		utils.Logging.Error().Err(err)
		return
	}
	utils.Logging.Info().Msgf("unidirectional stream accepted, id: %d", stream.StreamID())
	indication, err := receiveClientIndication(stream)
	if err != nil {
		utils.Logging.Error().Err(err)
		return
	}
	utils.Logging.Info().Msgf("client indication: %+v", indication)
	if err := s.validateClientIndication(indication); err != nil {
		utils.Logging.Error().Err(err)
		return
	}
	err = s.communicate(sess)
	if err != nil {
		utils.Logging.Error().Err(err)
		return
	}
}

func (s *WebTransportServerQuic) communicate(sess quic.Session) error {
	for {
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			return err
		}
		utils.Logging.Info().Msgf("bidirectional stream accepted: %d", stream.StreamID())
		if _, err := io.Copy(loggingWriter{stream}, loggingReader{stream}); err != nil {
			return err
		}
		utils.Logging.Info().Msgf("bidirectional stream closed: %d", stream.StreamID())
	}
}

// The client indication is a sequence of key-value pairs that are
// formatted in the following way:
//
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Key (16)            |          Length (16)          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           Value (*)                         ...
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func receiveClientIndication(stream quic.ReceiveStream) (ClientIndication, error) {
	var clientIndication ClientIndication
	reader := io.LimitReader(stream, maxClientIndicationLength)

	done := false

	for {
		if done {
			break
		}

		var key int16
		err := binary.Read(reader, binary.BigEndian, &key)
		if err != nil {
			if err == io.EOF {
				done = true
			} else {
				return clientIndication, err
			}
		}

		var valueLength int16
		err = binary.Read(reader, binary.BigEndian, &valueLength)
		if err != nil {
			return clientIndication, err
		}

		buf := make([]byte, valueLength)
		n, err := reader.Read(buf)
		if err != nil {
			if err == io.EOF {
				done = true
			} else {
				return clientIndication, err
			}
		}
		if int16(n) != valueLength {
			return clientIndication, errors.New("read less than expected")
		}
		value := string(buf)

		switch clientIndicationKey(key) {
		case clientIndicationKeyOrigin:
			clientIndication.Origin = value
		case clientIndicationKeyPath:
			clientIndication.Path = value
		default:
			utils.Logging.Info().Msgf("skip unknown client indication key: %d: %s", key, value)
		}
	}
	return clientIndication, nil
}

func (s *WebTransportServerQuic) generateTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair(s.config.TLSCertPath, s.config.TLSKeyPath)
	if err != nil {
		utils.Logging.Fatal().Err(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{alpnQuicTransport},
	}
}

func (s *WebTransportServerQuic) generateQuicConfig() *quic.Config {
	quicConf := &quic.Config{}
	quicConf.Tracer = qlog.NewTracer(func(_ logging.Perspective, connID []byte) io.WriteCloser {
		filename := fmt.Sprintf("server_%x.qlog", connID)
		f, err := os.Create(filename)
		if err != nil {
			utils.Logging.Fatal().Err(err)
		}
		utils.Logging.Info().Msgf("Creating qlog file %s.\n", filename)
		return utils.NewBufferedWriteCloser(bufio.NewWriter(f), f)
	})
}

var errBadOrigin = errors.New("bad origin")

func (s *WebTransportServerQuic) validateClientIndication(indication ClientIndication) error {
	u, err := url.Parse(indication.Origin)
	if err != nil {
		return errBadOrigin
	}
	if !stringInSlice(u.Host, s.config.AllowedOrigins) {
		return errBadOrigin
	}
	return nil
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	utils.Logging.Info().Str("--->", string(b))
	return w.Writer.Write(b)
}

// A wrapper for io.Reader that also logs the message.
type loggingReader struct{ io.Reader }

func (r loggingReader) Read(buf []byte) (n int, err error) {
	n, err = r.Reader.Read(buf)
	if n > 0 {
		utils.Logging.Info().Str("<---",string(buf[:n]))
	}
	return
}


