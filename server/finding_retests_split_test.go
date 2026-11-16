package server

import (
	"reflect"
	"testing"
)

// TestSplitCommands 是 splitCommands 的表驱动用例：只验纯函数，
// 不连库、不录屏（TestMain 拿不到 DSN 时会直接跑用例）。
func TestSplitCommands(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		want   []recStep
		reason string
	}{
		{
			name: "单条命令原样一条",
			in:   "python3 poc/softcenter_proxy_unauth_rce.py 127.0.0.1 80",
			want: []recStep{{Conn: ";", Command: "python3 poc/softcenter_proxy_unauth_rce.py 127.0.0.1 80"}},
		},
		{
			name: "分号拆开（真实复测命令）",
			in:   `curl -sI http://127.0.0.1/_root/Module_Softcenter.asp | head -3; echo "rc=$?"`,
			want: []recStep{
				{Conn: ";", Command: `curl -sI http://127.0.0.1/_root/Module_Softcenter.asp | head -3`},
				{Conn: ";", Command: `echo "rc=$?"`},
			},
		},
		{
			name: "管道不拆",
			in:   `printf 'GET / HTTP/1.1\r\n\r\n' | nc -q 2 127.0.0.1 80 | head -5`,
			want: []recStep{{Conn: ";", Command: `printf 'GET / HTTP/1.1\r\n\r\n' | nc -q 2 127.0.0.1 80 | head -5`}},
		},
		{
			name: "&& 与 || 保留连接符",
			in:   "python3 poc/a.py --out out.bin && xxd -l 128 out.bin || cat out.bin",
			want: []recStep{
				{Conn: ";", Command: "python3 poc/a.py --out out.bin"},
				{Conn: "&&", Command: "xxd -l 128 out.bin"},
				{Conn: "||", Command: "cat out.bin"},
			},
		},
		{
			name: "cd && 命令 ; echo",
			in:   `cd /home/david/iot-agent/data/tasks/115 && python3 poc/x.py 127.0.0.1 80; echo "rc=$?"`,
			want: []recStep{
				{Conn: ";", Command: "cd /home/david/iot-agent/data/tasks/115"},
				{Conn: "&&", Command: "python3 poc/x.py 127.0.0.1 80"},
				{Conn: ";", Command: `echo "rc=$?"`},
			},
		},
		{
			name: "引号里的分隔符不拆",
			in:   `echo "a;b && c"`,
			want: []recStep{{Conn: ";", Command: `echo "a;b && c"`}},
		},
		{
			name: "命令替换里的分隔符不拆",
			in:   "echo $(date; id)",
			want: []recStep{{Conn: ";", Command: "echo $(date; id)"}},
		},
		{
			name: "重定向 2>&1 不误判后台",
			in:   "python3 poc/a.py 2>&1 | tee log.txt",
			want: []recStep{{Conn: ";", Command: "python3 poc/a.py 2>&1 | tee log.txt"}},
		},
		{name: "heredoc 整条不拆", in: "cat > /tmp/x <<EOF\nhello\nEOF", reason: "含 heredoc / herestring"},
		{name: "复合语句整条不拆", in: "for f in a b; do echo $f; done", reason: "复合语句（for）"},
		{name: "后台执行整条不拆", in: "nohup ./srv >/dev/null 2>&1 &", reason: "含后台执行 &"},
		{name: "续行符结尾不拆", in: "ls -l \\", reason: "以续行符结尾"},
		{name: "引号未闭合不拆", in: `echo "abc`, reason: "引号未闭合"},
		{name: "exit 不直敲", in: "exit", reason: "会改变会话 shell 状态（exit）"},
		{name: "set -e 不直敲", in: "set -e", reason: "会改变会话 shell 状态（set）"},
		{name: "空命令", in: "   ", reason: "命令为空"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := splitCommands(tc.in)
			if tc.reason != "" {
				if reason != tc.reason {
					t.Fatalf("reason = %q, want %q (steps=%v)", reason, tc.reason, got)
				}
				return
			}
			if reason != "" {
				t.Fatalf("unexpected reason %q", reason)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("steps = %#v\nwant %#v", got, tc.want)
			}
		})
	}
}

// TestNotTypableReason 覆盖「哪些命令绝不能直敲进会话 shell」的判定。
func TestNotTypableReason(t *testing.T) {
	ok := []string{"ls -l", "cd /tmp", "curl -s http://127.0.0.1/", "python3 poc/x.py", "echo done &>/dev/null"}
	for _, c := range ok {
		if why := notTypableReason(c); why != "" {
			t.Fatalf("%q 不该被拒：%s", c, why)
		}
	}
	bad := []string{"exit", "exec bash", "set -e", "trap '' INT", "shopt -s x", "bind x", "./run &"}
	for _, c := range bad {
		if why := notTypableReason(c); why == "" {
			t.Fatalf("%q 应该被拒（会污染会话 shell 或后台执行）", c)
		}
	}
}

// TestDiscardedRefsAmong 纯函数用例：evidence 只校验「引用到的、已丢弃的」录屏 id。
func TestDiscardedRefsAmong(t *testing.T) {
	discarded := map[int64]struct{}{14: {}, 15: {}}
	cases := []struct {
		name string
		text string
		want []int64
	}{
		{
			name: "引用已丢弃的录屏",
			text: "## 复测录屏\n- 文件：recordings/31/14.mp4（28.9s, 1280x800）",
			want: []int64{14},
		},
		{
			name: "引用有效录屏",
			text: "- 文件：recordings/31/16.mp4（30.1s）",
		},
		{
			name: "多条按出现顺序去重",
			text: "recordings/31/15.mp4 与 recordings/31/14.mp4，再看 recordings/31/15.mp4",
			want: []int64{15, 14},
		},
		{
			name: "非数字文件名不算引用",
			text: "recordings/31/abc.mp4",
		},
		{
			name: "没有引用",
			text: "本次复测未录屏，见上文步骤。",
		},
		{
			name: "纯函数传入空集合",
			text: "recordings/31/14.mp4",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set := discarded
			if tc.name == "纯函数传入空集合" {
				set = nil
			}
			got := discardedRefsAmong(tc.text, set)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}
