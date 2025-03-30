
-- name: ChangePassword :exec
UPDATE "partner"
SET password = COALESCE( $2, password )
WHERE id=$1 
RETURNING *;

-- name: ActivatePartner :exec
UPDATE "partner"
SET active = TRUE
WHERE id=$1 
RETURNING *;

-- name: SetNewStripeAccount :exec
UPDATE "partner"
SET stripe_id=$2
WHERE id=$1 
RETURNING *;

-- name: GetPartnerStripeCustumerID :one
SELECT stripe_id 
FROM "partner"
WHERE id=$1;


-- name: CheckUserEmail :one
SELECT EXISTS (
    SELECT 1 
    FROM "partner" 
    WHERE email = $1
);

