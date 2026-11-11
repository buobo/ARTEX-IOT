package db

import (
	"testing"
)

func TestInheritedActivityReadsRequireTerminalIntent(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) - skipping", err)
	}
	defer d.Close()

	expID, err := d.CreateExploration("source activity boundary", "source activity boundary")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = d.Exec(`DELETE FROM explorations WHERE id=$1`, expID) })
	store := d.Exploration(expID)
	intentID, err := store.AddIntent(map[string]any{"summary": "source work"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	appendStep := func(kind, summary string) int64 {
		t.Helper()
		id, appendErr := store.AppendActivity(Activity{
			NodeID: &intentID, Worker: "worker", Kind: kind, Summary: summary, Detail: summary + " detail",
		})
		if appendErr != nil {
			t.Fatal(appendErr)
		}
		return id
	}
	textID := appendStep("text", "shared text")
	thinkingID := appendStep("thinking", "private reasoning")
	usageID := appendStep("usage", "private accounting")
	resultID := appendStep("result", "shared result")
	if err := store.SetIntentState(intentID, "done"); err != nil {
		t.Fatal(err)
	}

	page, more, err := store.ActivityPageForTerminalIntent(intentID, 0, 10)
	if err != nil || more || len(page) != 2 || page[0].ID != textID || page[1].ID != resultID {
		t.Fatalf("terminal page boundary: page=%+v more=%v err=%v", page, more, err)
	}
	list, cursor, err := store.ActivityListForTerminalIntent(intentID, 0, 10)
	if err != nil || len(list) != 2 || cursor != resultID {
		t.Fatalf("terminal list boundary: list=%+v cursor=%d err=%v", list, cursor, err)
	}
	trace, err := store.ActivityTraceForTerminalIntent(intentID, 10)
	if err != nil || len(trace) != 2 {
		t.Fatalf("terminal trace boundary: trace=%+v err=%v", trace, err)
	}
	hits, err := store.ActivityTraceSearchForTerminalIntent(intentID, "shared", 10)
	if err != nil || len(hits) != 2 {
		t.Fatalf("terminal search boundary: hits=%+v err=%v", hits, err)
	}
	details, err := store.ActivityByIDsForTerminalIntents([]int64{textID, thinkingID, usageID, resultID})
	if err != nil || len(details) != 2 || details[0].ID != textID || details[1].ID != resultID {
		t.Fatalf("terminal detail boundary: details=%+v err=%v", details, err)
	}

	// Reopening a source intent must close every inherited activity read even if
	// callers still hold a stale terminal-state snapshot.
	if err := store.SetIntentState(intentID, "running"); err != nil {
		t.Fatal(err)
	}
	page, _, err = store.ActivityPageForTerminalIntent(intentID, 0, 10)
	if err != nil || len(page) != 0 {
		t.Fatalf("reopened intent leaked through page: page=%+v err=%v", page, err)
	}
	list, _, err = store.ActivityListForTerminalIntent(intentID, 0, 10)
	if err != nil || len(list) != 0 {
		t.Fatalf("reopened intent leaked through list: list=%+v err=%v", list, err)
	}
	trace, err = store.ActivityTraceForTerminalIntent(intentID, 10)
	if err != nil || len(trace) != 0 {
		t.Fatalf("reopened intent leaked through trace: trace=%+v err=%v", trace, err)
	}
	hits, err = store.ActivityTraceSearchForTerminalIntent(intentID, "shared", 10)
	if err != nil || len(hits) != 0 {
		t.Fatalf("reopened intent leaked through search: hits=%+v err=%v", hits, err)
	}
	details, err = store.ActivityByIDsForTerminalIntents([]int64{textID, resultID})
	if err != nil || len(details) != 0 {
		t.Fatalf("reopened intent leaked through detail: details=%+v err=%v", details, err)
	}
}

