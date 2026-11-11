package db

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestCompanyScopeLimitsAndCheckedErrors(t *testing.T) {
	boundary := strings.Repeat("界", MaxCompanyScopeRawRunes)
	if err := ValidateCompanyScopeInputBounds([]ScopeInput{{Kind: "keyword", Value: boundary}}); err != nil {
		t.Fatalf("exact raw rune boundary rejected: %v", err)
	}
	var validationErr *CompanyScopeValidationError
	if err := ValidateCompanyScopeInputBounds([]ScopeInput{{Kind: "keyword", Value: boundary + "界"}}); !errors.As(err, &validationErr) {
		t.Fatalf("oversized raw value error=%v want CompanyScopeValidationError", err)
	}
	// 条数不再设上限,只校验单条长度。
	if err := ValidateCompanyScopeInputBounds(make([]ScopeInput, 1000)); err != nil {
		t.Fatalf("rule count should be unbounded, got %v", err)
	}

	d, _, companies := testSetup(t)
	defer d.Close()
	stamp := time.Now().UnixNano()
	companyID, _, err := companies.UpsertCompany(fmt.Sprintf("Scope Limits %d", stamp), "")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanupCompany(d, companyID)
	// 曾经封顶 256 条,逐个 IP / 域名录范围的企业很容易撞上;现在不限条数。
	const bulk = 300
	rules := make([]ScopeInput, bulk)
	for i := range rules {
		rules[i] = ScopeInput{Kind: "keyword", Value: fmt.Sprintf("limit-%d-%d", stamp, i)}
	}
	if added, _, _, _, err := companies.AddScopeInputsChecked(companyID, rules, "test"); err != nil || added != bulk {
		t.Fatalf("bulk scope insert: added=%d want=%d err=%v", added, bulk, err)
	}
	if added, _, _, _, err := companies.AddScopeInputsChecked(companyID, []ScopeInput{
		{Kind: "keyword", Value: fmt.Sprintf("limit-%d-extra", stamp)},
	}, "test"); added != 1 || err != nil {
		t.Fatalf("append past the old cap: added=%d err=%v", added, err)
	}
	var count int
	if err := d.QueryRow(`SELECT count(*) FROM company_scope WHERE company_id=$1`, companyID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != bulk+1 {
		t.Fatalf("scope count=%d want=%d", count, bulk+1)
	}

	missingID := companyID + 1_000_000_000
	if _, _, _, _, err := companies.AddScopeInputsChecked(missingID, nil, "test"); !errors.Is(err, ErrCompanyNotFound) {
		t.Fatalf("missing add error=%v want ErrCompanyNotFound", err)
	}
	if _, _, _, err := companies.UpdateScopeInputsChecked(missingID, nil, "test"); !errors.Is(err, ErrCompanyNotFound) {
		t.Fatalf("missing update error=%v want ErrCompanyNotFound", err)
	}
	if _, err := companies.DeleteCompanyWithComponents(missingID, true); !errors.Is(err, ErrCompanyNotFound) {
		t.Fatalf("missing delete error=%v want ErrCompanyNotFound", err)
	}
}

func TestCompanyScopeCheckedReturnsSystemErrorSeparately(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v)", err)
	}
	companies := d.Companies()
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	_, _, _, validationErrors, err := companies.AddScopeInputsChecked(1, nil, "test")
	if err == nil {
		t.Fatal("closed database did not return a system error")
	}
	if len(validationErrors) != 0 {
		t.Fatalf("system error leaked into validation errors: %v", validationErrors)
	}
	var validationErr *CompanyScopeValidationError
	if errors.As(err, &validationErr) || errors.Is(err, ErrCompanyNotFound) {
		t.Fatalf("system error misclassified: %v", err)
	}
}
