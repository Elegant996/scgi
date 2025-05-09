// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package scgi

import (
	"bytes"
	"maps"
	"strconv"

	"github.com/jub0bs/iterutil"
)

// streamWriter abstracts out the separation of a stream into discrete netstrings.
type streamWriter struct {
	c   *client
	buf *bytes.Buffer
}

func (w *streamWriter) Write(p []byte) (int, error) {
	return w.buf.Write(p)

}

func (w *streamWriter) writeNetstring(pairs map[string]string) error {
	nn := 0
	if v, ok := pairs["CONTENT_LENGTH"]; ok {
		n, _ := w.buf.WriteString("CONTENT_LENGTH")
		w.buf.WriteByte(0x00)
		m, _ := w.buf.WriteString(v)
		w.buf.WriteByte(0x00)
		nn += n + m + 2
	}

	headers := maps.All(pairs)
	clStr := func(h string, _ string) bool { return h != "CONTENT_LENGTH" }
	for k, v := range iterutil.Filter2(headers, clStr) {
		n, _ := w.buf.WriteString(k)
		w.buf.WriteByte(0x00)
		m, _ := w.buf.WriteString(v)
		w.buf.WriteByte(0x00)
		nn += n + m + 2
	}

	// store string before resetting buffer
	s := w.buf.String()
	w.buf.Reset()

	// write the netstring
	w.buf.WriteString(strconv.Itoa(nn))
	w.buf.WriteByte(':')
	w.buf.WriteString(s)
	w.buf.WriteByte(',')

	_, err := w.buf.WriteTo(w.c.rwc)
	return err
}
