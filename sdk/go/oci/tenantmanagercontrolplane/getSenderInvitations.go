// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package tenantmanagercontrolplane

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Sender Invitations in Oracle Cloud Infrastructure Tenantmanagercontrolplane service.
//
// Return a (paginated) list of sender invitations.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/tenantmanagercontrolplane"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := tenantmanagercontrolplane.GetSenderInvitations(ctx, &tenantmanagercontrolplane.GetSenderInvitationsArgs{
//				CompartmentId:      compartmentId,
//				DisplayName:        pulumi.StringRef(senderInvitationDisplayName),
//				RecipientTenancyId: pulumi.StringRef(testTenancy.Id),
//				State:              pulumi.StringRef(senderInvitationState),
//				Status:             pulumi.StringRef(senderInvitationStatus),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetSenderInvitations(ctx *pulumi.Context, args *GetSenderInvitationsArgs, opts ...pulumi.InvokeOption) (*GetSenderInvitationsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetSenderInvitationsResult
	err := ctx.Invoke("oci:Tenantmanagercontrolplane/getSenderInvitations:getSenderInvitations", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSenderInvitations.
type GetSenderInvitationsArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string                      `pulumi:"displayName"`
	Filters     []GetSenderInvitationsFilter `pulumi:"filters"`
	// The tenancy that the invitation is addressed to.
	RecipientTenancyId *string `pulumi:"recipientTenancyId"`
	// The lifecycle state of the resource.
	State *string `pulumi:"state"`
	// The status of the sender invitation.
	Status *string `pulumi:"status"`
}

// A collection of values returned by getSenderInvitations.
type GetSenderInvitationsResult struct {
	// OCID of the sender tenancy.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-created name to describe the invitation. Avoid entering confidential information.
	DisplayName *string                      `pulumi:"displayName"`
	Filters     []GetSenderInvitationsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// OCID of the recipient tenancy.
	RecipientTenancyId *string `pulumi:"recipientTenancyId"`
	// The list of sender_invitation_collection.
	SenderInvitationCollections []GetSenderInvitationsSenderInvitationCollection `pulumi:"senderInvitationCollections"`
	// Lifecycle state of the sender invitation.
	State *string `pulumi:"state"`
	// Status of the sender invitation.
	Status *string `pulumi:"status"`
}

func GetSenderInvitationsOutput(ctx *pulumi.Context, args GetSenderInvitationsOutputArgs, opts ...pulumi.InvokeOption) GetSenderInvitationsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetSenderInvitationsResultOutput, error) {
			args := v.(GetSenderInvitationsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Tenantmanagercontrolplane/getSenderInvitations:getSenderInvitations", args, GetSenderInvitationsResultOutput{}, options).(GetSenderInvitationsResultOutput), nil
		}).(GetSenderInvitationsResultOutput)
}

// A collection of arguments for invoking getSenderInvitations.
type GetSenderInvitationsOutputArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput                `pulumi:"displayName"`
	Filters     GetSenderInvitationsFilterArrayInput `pulumi:"filters"`
	// The tenancy that the invitation is addressed to.
	RecipientTenancyId pulumi.StringPtrInput `pulumi:"recipientTenancyId"`
	// The lifecycle state of the resource.
	State pulumi.StringPtrInput `pulumi:"state"`
	// The status of the sender invitation.
	Status pulumi.StringPtrInput `pulumi:"status"`
}

func (GetSenderInvitationsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSenderInvitationsArgs)(nil)).Elem()
}

// A collection of values returned by getSenderInvitations.
type GetSenderInvitationsResultOutput struct{ *pulumi.OutputState }

func (GetSenderInvitationsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSenderInvitationsResult)(nil)).Elem()
}

func (o GetSenderInvitationsResultOutput) ToGetSenderInvitationsResultOutput() GetSenderInvitationsResultOutput {
	return o
}

func (o GetSenderInvitationsResultOutput) ToGetSenderInvitationsResultOutputWithContext(ctx context.Context) GetSenderInvitationsResultOutput {
	return o
}

// OCID of the sender tenancy.
func (o GetSenderInvitationsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSenderInvitationsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A user-created name to describe the invitation. Avoid entering confidential information.
func (o GetSenderInvitationsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSenderInvitationsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetSenderInvitationsResultOutput) Filters() GetSenderInvitationsFilterArrayOutput {
	return o.ApplyT(func(v GetSenderInvitationsResult) []GetSenderInvitationsFilter { return v.Filters }).(GetSenderInvitationsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetSenderInvitationsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetSenderInvitationsResult) string { return v.Id }).(pulumi.StringOutput)
}

// OCID of the recipient tenancy.
func (o GetSenderInvitationsResultOutput) RecipientTenancyId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSenderInvitationsResult) *string { return v.RecipientTenancyId }).(pulumi.StringPtrOutput)
}

// The list of sender_invitation_collection.
func (o GetSenderInvitationsResultOutput) SenderInvitationCollections() GetSenderInvitationsSenderInvitationCollectionArrayOutput {
	return o.ApplyT(func(v GetSenderInvitationsResult) []GetSenderInvitationsSenderInvitationCollection {
		return v.SenderInvitationCollections
	}).(GetSenderInvitationsSenderInvitationCollectionArrayOutput)
}

// Lifecycle state of the sender invitation.
func (o GetSenderInvitationsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSenderInvitationsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// Status of the sender invitation.
func (o GetSenderInvitationsResultOutput) Status() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSenderInvitationsResult) *string { return v.Status }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetSenderInvitationsResultOutput{})
}
