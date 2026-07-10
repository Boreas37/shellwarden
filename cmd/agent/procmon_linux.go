//go:build linux

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// Constants from <linux/connector.h> and <linux/cn_proc.h>.
const (
	cnIdxProc = 0x1
	cnValProc = 0x1

	procCnMcastListen = 0x1
	procEventExec     = 0x00000002

	nlmsgHdrLen = 16 // sizeof(struct nlmsghdr)
	cnMsgHdrLen = 20 // sizeof(struct cn_msg)
	procEvtHdr  = 16 // what(4) + cpu(4) + timestamp_ns(8)
)

// monitorExecConnector subscribes to the kernel process events connector and
// reports every program launch in real time — no polling gap, so short-lived
// commands cannot slip through. Requires CAP_NET_ADMIN and host net/pid ns.
func monitorExecConnector(send func([]byte)) error {
	sock, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_DGRAM, unix.NETLINK_CONNECTOR)
	if err != nil {
		return fmt.Errorf("netlink socket: %w", err)
	}
	defer unix.Close(sock)

	if err := unix.Bind(sock, &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Pid:    uint32(os.Getpid()),
		Groups: cnIdxProc,
	}); err != nil {
		return fmt.Errorf("netlink bind: %w", err)
	}

	if err := subscribeProcEvents(sock); err != nil {
		return fmt.Errorf("subscribe proc events: %w", err)
	}
	log.Println("host command logging active (kernel proc connector, real-time)")

	buf := make([]byte, 8192)
	for {
		n, err := unix.Read(sock, buf)
		if err != nil {
			return fmt.Errorf("netlink read: %w", err)
		}
		parseNetlink(buf[:n], send)
	}
}

// subscribeProcEvents sends PROC_CN_MCAST_LISTEN to start receiving events.
func subscribeProcEvents(sock int) error {
	const dataLen = 4
	total := nlmsgHdrLen + cnMsgHdrLen + dataLen
	b := make([]byte, total)

	// struct nlmsghdr
	binary.LittleEndian.PutUint32(b[0:4], uint32(total))
	binary.LittleEndian.PutUint16(b[4:6], uint16(unix.NLMSG_DONE))
	binary.LittleEndian.PutUint16(b[6:8], 0)
	binary.LittleEndian.PutUint32(b[8:12], 0)
	binary.LittleEndian.PutUint32(b[12:16], uint32(os.Getpid()))

	// struct cn_msg
	o := nlmsgHdrLen
	binary.LittleEndian.PutUint32(b[o:o+4], cnIdxProc)
	binary.LittleEndian.PutUint32(b[o+4:o+8], cnValProc)
	binary.LittleEndian.PutUint32(b[o+8:o+12], 0)  // seq
	binary.LittleEndian.PutUint32(b[o+12:o+16], 0) // ack
	binary.LittleEndian.PutUint16(b[o+16:o+18], dataLen)
	binary.LittleEndian.PutUint16(b[o+18:o+20], 0)

	// data: enum proc_cn_mcast_op
	binary.LittleEndian.PutUint32(b[o+20:o+24], procCnMcastListen)

	return unix.Sendto(sock, b, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK})
}

// parseNetlink walks one or more nlmsghdr-framed messages in b.
func parseNetlink(b []byte, send func([]byte)) {
	for len(b) >= nlmsgHdrLen {
		nlLen := binary.LittleEndian.Uint32(b[0:4])
		nlType := binary.LittleEndian.Uint16(b[4:6])
		if nlLen < nlmsgHdrLen || int(nlLen) > len(b) {
			return
		}
		if nlType != unix.NLMSG_ERROR && nlType != unix.NLMSG_NOOP {
			handleProcEvent(b[nlmsgHdrLen:nlLen], send)
		}
		aligned := (int(nlLen) + 3) &^ 3
		if aligned >= len(b) {
			return
		}
		b = b[aligned:]
	}
}

// handleProcEvent decodes a cn_msg payload and emits launch events.
func handleProcEvent(payload []byte, send func([]byte)) {
	if len(payload) < cnMsgHdrLen+procEvtHdr+8 {
		return
	}
	pe := payload[cnMsgHdrLen:] // struct proc_event
	what := binary.LittleEndian.Uint32(pe[0:4])
	if what != procEventExec {
		return
	}
	data := pe[procEvtHdr:] // { process_pid, process_tgid }
	pid := int(int32(binary.LittleEndian.Uint32(data[0:4])))

	ev := buildExecEvent(pid)
	if ev == nil {
		// Process exited before we could read /proc — still record the launch.
		ev = &execEvent{Type: "exec", PID: pid, TS: time.Now().UTC().Format(time.RFC3339)}
	}
	ev.Source = "connector"
	if b, err := json.Marshal(ev); err == nil {
		send(b)
	}
}
