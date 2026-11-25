package gigahost

// Decoding of the GET /account payload.
//
// It lives beside the identity decoder rather than in the type file, which is
// already close to the repository's size ceiling, and because the only thing this
// decode does beyond the plain field mapping is accept the account identifier in
// both shapes the provider documents.

import "encoding/json"

// UnmarshalJSON accepts the account identifier in either documented shape: the
// provider sends cust_id as a number on GET /account and as text in other
// payloads, and both name the same account.
func (a *AccountInfo) UnmarshalJSON(data []byte) error {
	shadow := struct {
		ID               Identity `json:"id"`
		CustID           Identity `json:"cust_id"`
		CustName         string   `json:"cust_name"`
		Email            string   `json:"email"`
		Balance          float64  `json:"balance"`
		Credit           float64  `json:"credit"`
		CreditNOK        float64  `json:"credit_nok"`
		QualifiesArrears bool     `json:"qualifies_arrears"`
		Currency         string              `json:"currency"`
		Status           string              `json:"status"`
		Permissions      *AccountPermissions `json:"permissions"`
	}{}
	if err := json.Unmarshal(data, &shadow); err != nil {
		return err
	}
	a.ID = string(shadow.ID)
	a.CustID = string(shadow.CustID)
	a.CustName = shadow.CustName
	a.Email = shadow.Email
	a.Balance = shadow.Balance
	a.Credit = shadow.Credit
	a.CreditNOK = shadow.CreditNOK
	a.QualifiesArrears = shadow.QualifiesArrears
	a.Currency = shadow.Currency
	a.Status = shadow.Status
	a.Permissions = shadow.Permissions
	return nil
}
