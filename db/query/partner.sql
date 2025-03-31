-- name: GetPartner :one
-- Description: Retrieve a single partner record by primary key
SELECT 
	*
FROM 
	partner
WHERE 
	id = $1
LIMIT 1;

-- name: ListPartners :many
-- Description: Retrieve all partner records ordered by primary key
SELECT 
	*
FROM 
	partner
ORDER BY 
	id;

-- name: CreatePartner :one
-- Description: Insert a new partner record and return the created record
INSERT INTO 
	partner (id, name, email, password, balance, active, stripe_id, wise_id, reason
) 
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9
)
RETURNING *;

-- name: UpdatePartner :one
-- Description: Update a partner record by primary key and return the updated record
UPDATE 
	partner
SET name = $2, email = $3, password = $4, balance = $5, active = $6, stripe_id = $7, wise_id = $8, reason = $9
WHERE 
	id = $1
RETURNING *;

-- name: DeletePartner :exec
-- Description: Delete a partner record by primary key
DELETE FROM 
	partner
WHERE 
	id = $1;
