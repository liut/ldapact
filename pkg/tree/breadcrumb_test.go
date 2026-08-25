package tree

import "testing"

func TestBreadcrumbsShort(t *testing.T) {
	crumbs := Breadcrumbs("cn=alice,ou=People,dc=example,dc=com", "dc=example,dc=com", 5)
	if len(crumbs) != 3 {
		t.Fatalf("len = %d: %+v", len(crumbs), crumbs)
	}
	if crumbs[0].Label != "example" || crumbs[0].DN != "dc=example,dc=com" {
		t.Errorf("root crumb = %+v", crumbs[0])
	}
	if crumbs[2].DN != "cn=alice,ou=People,dc=example,dc=com" {
		t.Errorf("leaf crumb = %+v", crumbs[2])
	}
}

func TestBreadcrumbsDeep(t *testing.T) {
	dn := "uid=u9,ou=Unit9,ou=Dept9,ou=Org9,ou=Region9,ou=Country9,dc=example,dc=com"
	crumbs := Breadcrumbs(dn, "dc=example,dc=com", 5)
	if len(crumbs) != 6 { // 3 first + ellipsis + 2 last
		t.Fatalf("len = %d: %+v", len(crumbs), crumbs)
	}
	if crumbs[3].Label != Ellipsis {
		t.Errorf("crumb[3] should be ellipsis: %+v", crumbs)
	}
	if crumbs[4].Label != "Unit9" || crumbs[5].Label != "u9" {
		t.Errorf("last crumbs = %+v", crumbs[4:])
	}
}

func TestBreadcrumbsInvalidDN(t *testing.T) {
	crumbs := Breadcrumbs("garbage", "", 5)
	if len(crumbs) != 1 || crumbs[0].DN != "garbage" {
		t.Fatalf("invalid dn fallback: %+v", crumbs)
	}
}

func TestBreadcrumbsAtBase(t *testing.T) {
	crumbs := Breadcrumbs("dc=example,dc=com", "dc=example,dc=com", 5)
	if len(crumbs) != 1 || crumbs[0].DN != "dc=example,dc=com" {
		t.Fatalf("base trail = %+v", crumbs)
	}
}
