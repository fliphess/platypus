package audit

// Action names what happened. The names are stable: they are stored in the
// database and used in log searches.
type Action string

const (
	ActionAuthRejected Action = "auth.rejected"
	ActionLogin        Action = "auth.login"
	ActionLogout       Action = "auth.logout"
	ActionUserCreated  Action = "user.created"
	ActionUserProfile  Action = "user.profile_updated"
	ActionAccessDenied Action = "access.denied"

	ActionItemList     Action = "item.list"
	ActionItemView     Action = "item.view"
	ActionItemReveal   Action = "item.reveal"
	ActionItemCreate   Action = "item.create"
	ActionItemUpdate   Action = "item.update"
	ActionItemRollback Action = "item.rollback"
	ActionItemNote     Action = "item.note"
	ActionItemUndelete Action = "item.undelete"
	ActionItemHidden   Action = "item.hidden"

	ActionAdminModeEnter Action = "admin_mode.enter"
	ActionAdminModeLeave Action = "admin_mode.leave"

	ActionMFAFailed          Action = "mfa.failed"
	ActionUserLocked         Action = "user.locked"
	ActionTOTPEnrolled       Action = "mfa.totp_enrolled"
	ActionTOTPRemoved        Action = "mfa.totp_removed"
	ActionPasskeyAdded       Action = "mfa.passkey_added"
	ActionPasskeyRemoved     Action = "mfa.passkey_removed"
	ActionRecoveryCodesIssue Action = "mfa.recovery_codes_issued"
	ActionRecoveryCodeUsed   Action = "mfa.recovery_code_used"

	ActionBootstrapTokenIssued  Action = "bootstrap.token_issued"
	ActionBootstrapTokenEntered Action = "bootstrap.token_entered"
	ActionBootstrapCompleted    Action = "bootstrap.completed"
	ActionBootstrapReset        Action = "bootstrap.reset"

	ActionUserAdded        Action = "admin.user_added"
	ActionUserAdminChanged Action = "admin.user_admin_changed"
	ActionUserDisabled     Action = "admin.user_disabled"
	ActionUserEnabled      Action = "admin.user_enabled"
	ActionUserUnlocked     Action = "admin.user_unlocked"
	ActionUserPolicies     Action = "admin.user_policies_changed"
	ActionUserTeams        Action = "admin.user_teams_changed"

	ActionTeamCreated  Action = "admin.team_created"
	ActionTeamUpdated  Action = "admin.team_updated"
	ActionTeamDeleted  Action = "admin.team_deleted"
	ActionTeamPolicies Action = "admin.team_policies_changed"

	ActionPolicyCreated Action = "admin.policy_created"
	ActionPolicyUpdated Action = "admin.policy_updated"
	ActionPolicyDeleted Action = "admin.policy_deleted"
	ActionPoliciesSeed  Action = "admin.policies_seeded"

	ActionBlockOn       Action = "admin.block_on"
	ActionBlockOff      Action = "admin.block_off"
	ActionSyncRequested Action = "admin.sync_requested"
	ActionAuditPruned   Action = "admin.audit_pruned"
	ActionAuditExported Action = "admin.audit_exported"
)

// Actions lists every action, for the filter in the audit page.
var Actions = []Action{
	ActionAuthRejected, ActionLogin, ActionLogout, ActionUserCreated, ActionUserProfile, ActionAccessDenied,
	ActionItemList, ActionItemView, ActionItemReveal, ActionItemCreate, ActionItemUpdate, ActionItemUndelete,
	ActionItemRollback, ActionItemNote, ActionItemHidden,
	ActionAdminModeEnter, ActionAdminModeLeave,
	ActionMFAFailed, ActionUserLocked, ActionTOTPEnrolled, ActionTOTPRemoved,
	ActionPasskeyAdded, ActionPasskeyRemoved, ActionRecoveryCodesIssue, ActionRecoveryCodeUsed,
	ActionBootstrapTokenIssued, ActionBootstrapTokenEntered, ActionBootstrapCompleted, ActionBootstrapReset,
	ActionUserAdded, ActionUserAdminChanged, ActionUserDisabled, ActionUserEnabled, ActionUserUnlocked,
	ActionUserPolicies, ActionUserTeams,
	ActionTeamCreated, ActionTeamUpdated, ActionTeamDeleted, ActionTeamPolicies,
	ActionPolicyCreated, ActionPolicyUpdated, ActionPolicyDeleted, ActionPoliciesSeed,
	ActionBlockOn, ActionBlockOff, ActionSyncRequested, ActionAuditPruned, ActionAuditExported,
}
