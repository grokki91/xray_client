//go:build !windows

package osw

// TCPTable вне Windows не читается.
func TCPTable() ([]Conn, error) { return nil, ErrNoTable }
