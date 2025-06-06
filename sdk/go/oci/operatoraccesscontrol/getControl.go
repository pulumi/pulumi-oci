// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package operatoraccesscontrol

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Operator Control resource in Oracle Cloud Infrastructure Operator Access Control service.
//
// Gets the Operator Control associated with the specified Operator Control ID.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/operatoraccesscontrol"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := operatoraccesscontrol.GetControl(ctx, &operatoraccesscontrol.GetControlArgs{
//				OperatorControlId: testOperatorControlOciOperatorAccessControlOperatorControl.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetControl(ctx *pulumi.Context, args *GetControlArgs, opts ...pulumi.InvokeOption) (*GetControlResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetControlResult
	err := ctx.Invoke("oci:OperatorAccessControl/getControl:getControl", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getControl.
type GetControlArgs struct {
	// unique OperatorControl identifier
	OperatorControlId string `pulumi:"operatorControlId"`
}

// A collection of values returned by getControl.
type GetControlResult struct {
	// List of operator actions that need explicit approval. Any operator action not in the pre-approved list will require explicit approval. Access requests associated with a resource governed by this operator control will be require explicit approval if the access request contains any operator action in this list.
	ApprovalRequiredOpActionLists []string `pulumi:"approvalRequiredOpActionLists"`
	// List of user groups who can approve an access request associated with a target resource under the governance of this operator control.
	ApproverGroupsLists []string `pulumi:"approverGroupsLists"`
	// List of users who can approve an access request associated with a target resource under the governance of this operator control.
	ApproversLists []string `pulumi:"approversLists"`
	// The OCID of the compartment that contains the operator control.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace.
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Description of operator control.
	Description string `pulumi:"description"`
	// List of emailId.
	EmailIdLists []string `pulumi:"emailIdLists"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The OCID of the operator control.
	Id string `pulumi:"id"`
	// Whether the operator control is a default Operator Control.
	IsDefaultOperatorControl bool `pulumi:"isDefaultOperatorControl"`
	// Whether all the operator actions have been pre-approved. If yes, all access requests associated with a resource governed by this operator control  will be auto-approved.
	IsFullyPreApproved bool `pulumi:"isFullyPreApproved"`
	// Description associated with the latest modification of the operator control.
	LastModifiedInfo string `pulumi:"lastModifiedInfo"`
	// Number of approvers required to approve an access request.
	NumberOfApprovers int    `pulumi:"numberOfApprovers"`
	OperatorControlId string `pulumi:"operatorControlId"`
	// Name of the operator control. The name must be unique.
	OperatorControlName string `pulumi:"operatorControlName"`
	// List of pre-approved operator actions. Access requests associated with a resource governed by this operator control will be automatically approved if the access request only contain operator actions in the pre-approved list.
	PreApprovedOpActionLists []string `pulumi:"preApprovedOpActionLists"`
	// resourceType for which the OperatorControl is applicable
	ResourceType string `pulumi:"resourceType"`
	// The current lifecycle state of the operator control.
	State string `pulumi:"state"`
	// System message that would be displayed to the operator users on accessing the target resource under the governance of this operator control.
	SystemMessage string `pulumi:"systemMessage"`
	// Time when the operator control was created expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: '2020-05-22T21:10:29.600Z'
	TimeOfCreation string `pulumi:"timeOfCreation"`
	// Time when deleted expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339)timestamp format. Example: '2020-05-22T21:10:29.600Z'. Note a deleted operator control still stays in the system, so that you can still audit operator actions associated with access requests raised on target resources governed by the deleted operator control.
	TimeOfDeletion string `pulumi:"timeOfDeletion"`
	// Time when the operator control was last modified expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: '2020-05-22T21:10:29.600Z'
	TimeOfModification string `pulumi:"timeOfModification"`
}

func GetControlOutput(ctx *pulumi.Context, args GetControlOutputArgs, opts ...pulumi.InvokeOption) GetControlResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetControlResultOutput, error) {
			args := v.(GetControlArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:OperatorAccessControl/getControl:getControl", args, GetControlResultOutput{}, options).(GetControlResultOutput), nil
		}).(GetControlResultOutput)
}

// A collection of arguments for invoking getControl.
type GetControlOutputArgs struct {
	// unique OperatorControl identifier
	OperatorControlId pulumi.StringInput `pulumi:"operatorControlId"`
}

func (GetControlOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetControlArgs)(nil)).Elem()
}

// A collection of values returned by getControl.
type GetControlResultOutput struct{ *pulumi.OutputState }

func (GetControlResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetControlResult)(nil)).Elem()
}

func (o GetControlResultOutput) ToGetControlResultOutput() GetControlResultOutput {
	return o
}

func (o GetControlResultOutput) ToGetControlResultOutputWithContext(ctx context.Context) GetControlResultOutput {
	return o
}

// List of operator actions that need explicit approval. Any operator action not in the pre-approved list will require explicit approval. Access requests associated with a resource governed by this operator control will be require explicit approval if the access request contains any operator action in this list.
func (o GetControlResultOutput) ApprovalRequiredOpActionLists() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetControlResult) []string { return v.ApprovalRequiredOpActionLists }).(pulumi.StringArrayOutput)
}

// List of user groups who can approve an access request associated with a target resource under the governance of this operator control.
func (o GetControlResultOutput) ApproverGroupsLists() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetControlResult) []string { return v.ApproverGroupsLists }).(pulumi.StringArrayOutput)
}

// List of users who can approve an access request associated with a target resource under the governance of this operator control.
func (o GetControlResultOutput) ApproversLists() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetControlResult) []string { return v.ApproversLists }).(pulumi.StringArrayOutput)
}

// The OCID of the compartment that contains the operator control.
func (o GetControlResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetControlResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace.
func (o GetControlResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v GetControlResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// Description of operator control.
func (o GetControlResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v GetControlResult) string { return v.Description }).(pulumi.StringOutput)
}

// List of emailId.
func (o GetControlResultOutput) EmailIdLists() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetControlResult) []string { return v.EmailIdLists }).(pulumi.StringArrayOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.
func (o GetControlResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v GetControlResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The OCID of the operator control.
func (o GetControlResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetControlResult) string { return v.Id }).(pulumi.StringOutput)
}

// Whether the operator control is a default Operator Control.
func (o GetControlResultOutput) IsDefaultOperatorControl() pulumi.BoolOutput {
	return o.ApplyT(func(v GetControlResult) bool { return v.IsDefaultOperatorControl }).(pulumi.BoolOutput)
}

// Whether all the operator actions have been pre-approved. If yes, all access requests associated with a resource governed by this operator control  will be auto-approved.
func (o GetControlResultOutput) IsFullyPreApproved() pulumi.BoolOutput {
	return o.ApplyT(func(v GetControlResult) bool { return v.IsFullyPreApproved }).(pulumi.BoolOutput)
}

// Description associated with the latest modification of the operator control.
func (o GetControlResultOutput) LastModifiedInfo() pulumi.StringOutput {
	return o.ApplyT(func(v GetControlResult) string { return v.LastModifiedInfo }).(pulumi.StringOutput)
}

// Number of approvers required to approve an access request.
func (o GetControlResultOutput) NumberOfApprovers() pulumi.IntOutput {
	return o.ApplyT(func(v GetControlResult) int { return v.NumberOfApprovers }).(pulumi.IntOutput)
}

func (o GetControlResultOutput) OperatorControlId() pulumi.StringOutput {
	return o.ApplyT(func(v GetControlResult) string { return v.OperatorControlId }).(pulumi.StringOutput)
}

// Name of the operator control. The name must be unique.
func (o GetControlResultOutput) OperatorControlName() pulumi.StringOutput {
	return o.ApplyT(func(v GetControlResult) string { return v.OperatorControlName }).(pulumi.StringOutput)
}

// List of pre-approved operator actions. Access requests associated with a resource governed by this operator control will be automatically approved if the access request only contain operator actions in the pre-approved list.
func (o GetControlResultOutput) PreApprovedOpActionLists() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetControlResult) []string { return v.PreApprovedOpActionLists }).(pulumi.StringArrayOutput)
}

// resourceType for which the OperatorControl is applicable
func (o GetControlResultOutput) ResourceType() pulumi.StringOutput {
	return o.ApplyT(func(v GetControlResult) string { return v.ResourceType }).(pulumi.StringOutput)
}

// The current lifecycle state of the operator control.
func (o GetControlResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v GetControlResult) string { return v.State }).(pulumi.StringOutput)
}

// System message that would be displayed to the operator users on accessing the target resource under the governance of this operator control.
func (o GetControlResultOutput) SystemMessage() pulumi.StringOutput {
	return o.ApplyT(func(v GetControlResult) string { return v.SystemMessage }).(pulumi.StringOutput)
}

// Time when the operator control was created expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: '2020-05-22T21:10:29.600Z'
func (o GetControlResultOutput) TimeOfCreation() pulumi.StringOutput {
	return o.ApplyT(func(v GetControlResult) string { return v.TimeOfCreation }).(pulumi.StringOutput)
}

// Time when deleted expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339)timestamp format. Example: '2020-05-22T21:10:29.600Z'. Note a deleted operator control still stays in the system, so that you can still audit operator actions associated with access requests raised on target resources governed by the deleted operator control.
func (o GetControlResultOutput) TimeOfDeletion() pulumi.StringOutput {
	return o.ApplyT(func(v GetControlResult) string { return v.TimeOfDeletion }).(pulumi.StringOutput)
}

// Time when the operator control was last modified expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format. Example: '2020-05-22T21:10:29.600Z'
func (o GetControlResultOutput) TimeOfModification() pulumi.StringOutput {
	return o.ApplyT(func(v GetControlResult) string { return v.TimeOfModification }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetControlResultOutput{})
}
