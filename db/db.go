// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.26.0

package db

import (
	"context"
	"database/sql"
	"fmt"
)

type DBTX interface {
	ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	PrepareContext(context.Context, string) (*sql.Stmt, error)
	QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...interface{}) *sql.Row
}

func New(db DBTX) *Queries {
	return &Queries{db: db}
}

func Prepare(ctx context.Context, db DBTX) (*Queries, error) {
	q := Queries{db: db}
	var err error
	if q.activatePartnerStmt, err = db.PrepareContext(ctx, activatePartner); err != nil {
		return nil, fmt.Errorf("error preparing query ActivatePartner: %w", err)
	}
	if q.changePasswordStmt, err = db.PrepareContext(ctx, changePassword); err != nil {
		return nil, fmt.Errorf("error preparing query ChangePassword: %w", err)
	}
	if q.checkUserEmailStmt, err = db.PrepareContext(ctx, checkUserEmail); err != nil {
		return nil, fmt.Errorf("error preparing query CheckUserEmail: %w", err)
	}
	if q.createPartnerStmt, err = db.PrepareContext(ctx, createPartner); err != nil {
		return nil, fmt.Errorf("error preparing query CreatePartner: %w", err)
	}
	if q.deletePartnerStmt, err = db.PrepareContext(ctx, deletePartner); err != nil {
		return nil, fmt.Errorf("error preparing query DeletePartner: %w", err)
	}
	if q.getPartnerStmt, err = db.PrepareContext(ctx, getPartner); err != nil {
		return nil, fmt.Errorf("error preparing query GetPartner: %w", err)
	}
	if q.getPartnerByEmailStmt, err = db.PrepareContext(ctx, getPartnerByEmail); err != nil {
		return nil, fmt.Errorf("error preparing query GetPartnerByEmail: %w", err)
	}
	if q.getPartnerStripeCustumerIDStmt, err = db.PrepareContext(ctx, getPartnerStripeCustumerID); err != nil {
		return nil, fmt.Errorf("error preparing query GetPartnerStripeCustumerID: %w", err)
	}
	if q.listPartnersStmt, err = db.PrepareContext(ctx, listPartners); err != nil {
		return nil, fmt.Errorf("error preparing query ListPartners: %w", err)
	}
	if q.setNewStripeAccountStmt, err = db.PrepareContext(ctx, setNewStripeAccount); err != nil {
		return nil, fmt.Errorf("error preparing query SetNewStripeAccount: %w", err)
	}
	if q.updatePartnerStmt, err = db.PrepareContext(ctx, updatePartner); err != nil {
		return nil, fmt.Errorf("error preparing query UpdatePartner: %w", err)
	}
	return &q, nil
}

func (q *Queries) Close() error {
	var err error
	if q.activatePartnerStmt != nil {
		if cerr := q.activatePartnerStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing activatePartnerStmt: %w", cerr)
		}
	}
	if q.changePasswordStmt != nil {
		if cerr := q.changePasswordStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing changePasswordStmt: %w", cerr)
		}
	}
	if q.checkUserEmailStmt != nil {
		if cerr := q.checkUserEmailStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing checkUserEmailStmt: %w", cerr)
		}
	}
	if q.createPartnerStmt != nil {
		if cerr := q.createPartnerStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing createPartnerStmt: %w", cerr)
		}
	}
	if q.deletePartnerStmt != nil {
		if cerr := q.deletePartnerStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing deletePartnerStmt: %w", cerr)
		}
	}
	if q.getPartnerStmt != nil {
		if cerr := q.getPartnerStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing getPartnerStmt: %w", cerr)
		}
	}
	if q.getPartnerByEmailStmt != nil {
		if cerr := q.getPartnerByEmailStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing getPartnerByEmailStmt: %w", cerr)
		}
	}
	if q.getPartnerStripeCustumerIDStmt != nil {
		if cerr := q.getPartnerStripeCustumerIDStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing getPartnerStripeCustumerIDStmt: %w", cerr)
		}
	}
	if q.listPartnersStmt != nil {
		if cerr := q.listPartnersStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing listPartnersStmt: %w", cerr)
		}
	}
	if q.setNewStripeAccountStmt != nil {
		if cerr := q.setNewStripeAccountStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing setNewStripeAccountStmt: %w", cerr)
		}
	}
	if q.updatePartnerStmt != nil {
		if cerr := q.updatePartnerStmt.Close(); cerr != nil {
			err = fmt.Errorf("error closing updatePartnerStmt: %w", cerr)
		}
	}
	return err
}

func (q *Queries) exec(ctx context.Context, stmt *sql.Stmt, query string, args ...interface{}) (sql.Result, error) {
	switch {
	case stmt != nil && q.tx != nil:
		return q.tx.StmtContext(ctx, stmt).ExecContext(ctx, args...)
	case stmt != nil:
		return stmt.ExecContext(ctx, args...)
	default:
		return q.db.ExecContext(ctx, query, args...)
	}
}

func (q *Queries) query(ctx context.Context, stmt *sql.Stmt, query string, args ...interface{}) (*sql.Rows, error) {
	switch {
	case stmt != nil && q.tx != nil:
		return q.tx.StmtContext(ctx, stmt).QueryContext(ctx, args...)
	case stmt != nil:
		return stmt.QueryContext(ctx, args...)
	default:
		return q.db.QueryContext(ctx, query, args...)
	}
}

func (q *Queries) queryRow(ctx context.Context, stmt *sql.Stmt, query string, args ...interface{}) *sql.Row {
	switch {
	case stmt != nil && q.tx != nil:
		return q.tx.StmtContext(ctx, stmt).QueryRowContext(ctx, args...)
	case stmt != nil:
		return stmt.QueryRowContext(ctx, args...)
	default:
		return q.db.QueryRowContext(ctx, query, args...)
	}
}

type Queries struct {
	db                             DBTX
	tx                             *sql.Tx
	activatePartnerStmt            *sql.Stmt
	changePasswordStmt             *sql.Stmt
	checkUserEmailStmt             *sql.Stmt
	createPartnerStmt              *sql.Stmt
	deletePartnerStmt              *sql.Stmt
	getPartnerStmt                 *sql.Stmt
	getPartnerByEmailStmt          *sql.Stmt
	getPartnerStripeCustumerIDStmt *sql.Stmt
	listPartnersStmt               *sql.Stmt
	setNewStripeAccountStmt        *sql.Stmt
	updatePartnerStmt              *sql.Stmt
}

func (q *Queries) WithTx(tx *sql.Tx) *Queries {
	return &Queries{
		db:                             tx,
		tx:                             tx,
		activatePartnerStmt:            q.activatePartnerStmt,
		changePasswordStmt:             q.changePasswordStmt,
		checkUserEmailStmt:             q.checkUserEmailStmt,
		createPartnerStmt:              q.createPartnerStmt,
		deletePartnerStmt:              q.deletePartnerStmt,
		getPartnerStmt:                 q.getPartnerStmt,
		getPartnerByEmailStmt:          q.getPartnerByEmailStmt,
		getPartnerStripeCustumerIDStmt: q.getPartnerStripeCustumerIDStmt,
		listPartnersStmt:               q.listPartnersStmt,
		setNewStripeAccountStmt:        q.setNewStripeAccountStmt,
		updatePartnerStmt:              q.updatePartnerStmt,
	}
}
