// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package database

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Execution Action resource in Oracle Cloud Infrastructure Database service.
//
// Creates an execution action resource.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/database"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := database.NewExecutionAction(ctx, "test_execution_action", &database.ExecutionActionArgs{
//				ActionType:        pulumi.Any(executionActionActionType),
//				ExecutionWindowId: pulumi.Any(testExecutionWindow.Id),
//				ActionMembers: database.ExecutionActionActionMemberArray{
//					&database.ExecutionActionActionMemberArgs{
//						MemberId:             pulumi.Any(testMember.Id),
//						MemberOrder:          pulumi.Any(executionActionActionMembersMemberOrder),
//						EstimatedTimeInMins:  pulumi.Any(executionActionActionMembersEstimatedTimeInMins),
//						Status:               pulumi.Any(executionActionActionMembersStatus),
//						TotalTimeTakenInMins: pulumi.Any(executionActionActionMembersTotalTimeTakenInMins),
//					},
//				},
//				ActionParams:  pulumi.Any(executionActionActionParams),
//				CompartmentId: pulumi.Any(compartmentId),
//				DefinedTags:   pulumi.Any(executionActionDefinedTags),
//				FreeformTags: pulumi.StringMap{
//					"Department": pulumi.String("Finance"),
//				},
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// ExecutionActions can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Database/executionAction:ExecutionAction test_execution_action "id"
// ```
type ExecutionAction struct {
	pulumi.CustomResourceState

	// (Updatable) List of action members of this execution action.
	ActionMembers ExecutionActionActionMemberArrayOutput `pulumi:"actionMembers"`
	// (Updatable) Map<ParamName, ParamValue> where a key value pair describes the specific action parameter. Example: `{"count": "3"}`
	ActionParams pulumi.StringMapOutput `pulumi:"actionParams"`
	// The action type of the execution action being performed
	ActionType pulumi.StringOutput `pulumi:"actionType"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// Description of the execution action.
	Description pulumi.StringOutput `pulumi:"description"`
	// The user-friendly name for the execution action. The name does not need to be unique.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// The estimated time of the execution action in minutes.
	EstimatedTimeInMins pulumi.IntOutput `pulumi:"estimatedTimeInMins"`
	// The priority order of the execution action.
	ExecutionActionOrder pulumi.IntOutput `pulumi:"executionActionOrder"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the execution window resource the execution action belongs to.
	ExecutionWindowId pulumi.StringOutput `pulumi:"executionWindowId"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// Additional information about the current lifecycle state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The current sub-state of the execution action. Valid states are DURATION_EXCEEDED, MAINTENANCE_IN_PROGRESS and WAITING.
	LifecycleSubstate pulumi.StringOutput `pulumi:"lifecycleSubstate"`
	// The current state of the execution action. Valid states are SCHEDULED, IN_PROGRESS, FAILED, CANCELED, UPDATING, DELETED, SUCCEEDED and PARTIAL_SUCCESS.
	State pulumi.StringOutput `pulumi:"state"`
	// The date and time the execution action was created.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The last date and time that the execution action was updated.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
	// The total time taken by corresponding resource activity in minutes.
	TotalTimeTakenInMins pulumi.IntOutput `pulumi:"totalTimeTakenInMins"`
}

// NewExecutionAction registers a new resource with the given unique name, arguments, and options.
func NewExecutionAction(ctx *pulumi.Context,
	name string, args *ExecutionActionArgs, opts ...pulumi.ResourceOption) (*ExecutionAction, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ActionType == nil {
		return nil, errors.New("invalid value for required argument 'ActionType'")
	}
	if args.ExecutionWindowId == nil {
		return nil, errors.New("invalid value for required argument 'ExecutionWindowId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource ExecutionAction
	err := ctx.RegisterResource("oci:Database/executionAction:ExecutionAction", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetExecutionAction gets an existing ExecutionAction resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetExecutionAction(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ExecutionActionState, opts ...pulumi.ResourceOption) (*ExecutionAction, error) {
	var resource ExecutionAction
	err := ctx.ReadResource("oci:Database/executionAction:ExecutionAction", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ExecutionAction resources.
type executionActionState struct {
	// (Updatable) List of action members of this execution action.
	ActionMembers []ExecutionActionActionMember `pulumi:"actionMembers"`
	// (Updatable) Map<ParamName, ParamValue> where a key value pair describes the specific action parameter. Example: `{"count": "3"}`
	ActionParams map[string]string `pulumi:"actionParams"`
	// The action type of the execution action being performed
	ActionType *string `pulumi:"actionType"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Description of the execution action.
	Description *string `pulumi:"description"`
	// The user-friendly name for the execution action. The name does not need to be unique.
	DisplayName *string `pulumi:"displayName"`
	// The estimated time of the execution action in minutes.
	EstimatedTimeInMins *int `pulumi:"estimatedTimeInMins"`
	// The priority order of the execution action.
	ExecutionActionOrder *int `pulumi:"executionActionOrder"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the execution window resource the execution action belongs to.
	ExecutionWindowId *string `pulumi:"executionWindowId"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// Additional information about the current lifecycle state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The current sub-state of the execution action. Valid states are DURATION_EXCEEDED, MAINTENANCE_IN_PROGRESS and WAITING.
	LifecycleSubstate *string `pulumi:"lifecycleSubstate"`
	// The current state of the execution action. Valid states are SCHEDULED, IN_PROGRESS, FAILED, CANCELED, UPDATING, DELETED, SUCCEEDED and PARTIAL_SUCCESS.
	State *string `pulumi:"state"`
	// The date and time the execution action was created.
	TimeCreated *string `pulumi:"timeCreated"`
	// The last date and time that the execution action was updated.
	TimeUpdated *string `pulumi:"timeUpdated"`
	// The total time taken by corresponding resource activity in minutes.
	TotalTimeTakenInMins *int `pulumi:"totalTimeTakenInMins"`
}

type ExecutionActionState struct {
	// (Updatable) List of action members of this execution action.
	ActionMembers ExecutionActionActionMemberArrayInput
	// (Updatable) Map<ParamName, ParamValue> where a key value pair describes the specific action parameter. Example: `{"count": "3"}`
	ActionParams pulumi.StringMapInput
	// The action type of the execution action being performed
	ActionType pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags pulumi.StringMapInput
	// Description of the execution action.
	Description pulumi.StringPtrInput
	// The user-friendly name for the execution action. The name does not need to be unique.
	DisplayName pulumi.StringPtrInput
	// The estimated time of the execution action in minutes.
	EstimatedTimeInMins pulumi.IntPtrInput
	// The priority order of the execution action.
	ExecutionActionOrder pulumi.IntPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the execution window resource the execution action belongs to.
	ExecutionWindowId pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
	// Additional information about the current lifecycle state.
	LifecycleDetails pulumi.StringPtrInput
	// The current sub-state of the execution action. Valid states are DURATION_EXCEEDED, MAINTENANCE_IN_PROGRESS and WAITING.
	LifecycleSubstate pulumi.StringPtrInput
	// The current state of the execution action. Valid states are SCHEDULED, IN_PROGRESS, FAILED, CANCELED, UPDATING, DELETED, SUCCEEDED and PARTIAL_SUCCESS.
	State pulumi.StringPtrInput
	// The date and time the execution action was created.
	TimeCreated pulumi.StringPtrInput
	// The last date and time that the execution action was updated.
	TimeUpdated pulumi.StringPtrInput
	// The total time taken by corresponding resource activity in minutes.
	TotalTimeTakenInMins pulumi.IntPtrInput
}

func (ExecutionActionState) ElementType() reflect.Type {
	return reflect.TypeOf((*executionActionState)(nil)).Elem()
}

type executionActionArgs struct {
	// (Updatable) List of action members of this execution action.
	ActionMembers []ExecutionActionActionMember `pulumi:"actionMembers"`
	// (Updatable) Map<ParamName, ParamValue> where a key value pair describes the specific action parameter. Example: `{"count": "3"}`
	ActionParams map[string]string `pulumi:"actionParams"`
	// The action type of the execution action being performed
	ActionType string `pulumi:"actionType"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the execution window resource the execution action belongs to.
	ExecutionWindowId string `pulumi:"executionWindowId"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags map[string]string `pulumi:"freeformTags"`
}

// The set of arguments for constructing a ExecutionAction resource.
type ExecutionActionArgs struct {
	// (Updatable) List of action members of this execution action.
	ActionMembers ExecutionActionActionMemberArrayInput
	// (Updatable) Map<ParamName, ParamValue> where a key value pair describes the specific action parameter. Example: `{"count": "3"}`
	ActionParams pulumi.StringMapInput
	// The action type of the execution action being performed
	ActionType pulumi.StringInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
	DefinedTags pulumi.StringMapInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the execution window resource the execution action belongs to.
	ExecutionWindowId pulumi.StringInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	FreeformTags pulumi.StringMapInput
}

func (ExecutionActionArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*executionActionArgs)(nil)).Elem()
}

type ExecutionActionInput interface {
	pulumi.Input

	ToExecutionActionOutput() ExecutionActionOutput
	ToExecutionActionOutputWithContext(ctx context.Context) ExecutionActionOutput
}

func (*ExecutionAction) ElementType() reflect.Type {
	return reflect.TypeOf((**ExecutionAction)(nil)).Elem()
}

func (i *ExecutionAction) ToExecutionActionOutput() ExecutionActionOutput {
	return i.ToExecutionActionOutputWithContext(context.Background())
}

func (i *ExecutionAction) ToExecutionActionOutputWithContext(ctx context.Context) ExecutionActionOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExecutionActionOutput)
}

// ExecutionActionArrayInput is an input type that accepts ExecutionActionArray and ExecutionActionArrayOutput values.
// You can construct a concrete instance of `ExecutionActionArrayInput` via:
//
//	ExecutionActionArray{ ExecutionActionArgs{...} }
type ExecutionActionArrayInput interface {
	pulumi.Input

	ToExecutionActionArrayOutput() ExecutionActionArrayOutput
	ToExecutionActionArrayOutputWithContext(context.Context) ExecutionActionArrayOutput
}

type ExecutionActionArray []ExecutionActionInput

func (ExecutionActionArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ExecutionAction)(nil)).Elem()
}

func (i ExecutionActionArray) ToExecutionActionArrayOutput() ExecutionActionArrayOutput {
	return i.ToExecutionActionArrayOutputWithContext(context.Background())
}

func (i ExecutionActionArray) ToExecutionActionArrayOutputWithContext(ctx context.Context) ExecutionActionArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExecutionActionArrayOutput)
}

// ExecutionActionMapInput is an input type that accepts ExecutionActionMap and ExecutionActionMapOutput values.
// You can construct a concrete instance of `ExecutionActionMapInput` via:
//
//	ExecutionActionMap{ "key": ExecutionActionArgs{...} }
type ExecutionActionMapInput interface {
	pulumi.Input

	ToExecutionActionMapOutput() ExecutionActionMapOutput
	ToExecutionActionMapOutputWithContext(context.Context) ExecutionActionMapOutput
}

type ExecutionActionMap map[string]ExecutionActionInput

func (ExecutionActionMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ExecutionAction)(nil)).Elem()
}

func (i ExecutionActionMap) ToExecutionActionMapOutput() ExecutionActionMapOutput {
	return i.ToExecutionActionMapOutputWithContext(context.Background())
}

func (i ExecutionActionMap) ToExecutionActionMapOutputWithContext(ctx context.Context) ExecutionActionMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ExecutionActionMapOutput)
}

type ExecutionActionOutput struct{ *pulumi.OutputState }

func (ExecutionActionOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ExecutionAction)(nil)).Elem()
}

func (o ExecutionActionOutput) ToExecutionActionOutput() ExecutionActionOutput {
	return o
}

func (o ExecutionActionOutput) ToExecutionActionOutputWithContext(ctx context.Context) ExecutionActionOutput {
	return o
}

// (Updatable) List of action members of this execution action.
func (o ExecutionActionOutput) ActionMembers() ExecutionActionActionMemberArrayOutput {
	return o.ApplyT(func(v *ExecutionAction) ExecutionActionActionMemberArrayOutput { return v.ActionMembers }).(ExecutionActionActionMemberArrayOutput)
}

// (Updatable) Map<ParamName, ParamValue> where a key value pair describes the specific action parameter. Example: `{"count": "3"}`
func (o ExecutionActionOutput) ActionParams() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExecutionAction) pulumi.StringMapOutput { return v.ActionParams }).(pulumi.StringMapOutput)
}

// The action type of the execution action being performed
func (o ExecutionActionOutput) ActionType() pulumi.StringOutput {
	return o.ApplyT(func(v *ExecutionAction) pulumi.StringOutput { return v.ActionType }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o ExecutionActionOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExecutionAction) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).
func (o ExecutionActionOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExecutionAction) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// Description of the execution action.
func (o ExecutionActionOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *ExecutionAction) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// The user-friendly name for the execution action. The name does not need to be unique.
func (o ExecutionActionOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *ExecutionAction) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// The estimated time of the execution action in minutes.
func (o ExecutionActionOutput) EstimatedTimeInMins() pulumi.IntOutput {
	return o.ApplyT(func(v *ExecutionAction) pulumi.IntOutput { return v.EstimatedTimeInMins }).(pulumi.IntOutput)
}

// The priority order of the execution action.
func (o ExecutionActionOutput) ExecutionActionOrder() pulumi.IntOutput {
	return o.ApplyT(func(v *ExecutionAction) pulumi.IntOutput { return v.ExecutionActionOrder }).(pulumi.IntOutput)
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the execution window resource the execution action belongs to.
func (o ExecutionActionOutput) ExecutionWindowId() pulumi.StringOutput {
	return o.ApplyT(func(v *ExecutionAction) pulumi.StringOutput { return v.ExecutionWindowId }).(pulumi.StringOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o ExecutionActionOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *ExecutionAction) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// Additional information about the current lifecycle state.
func (o ExecutionActionOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *ExecutionAction) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The current sub-state of the execution action. Valid states are DURATION_EXCEEDED, MAINTENANCE_IN_PROGRESS and WAITING.
func (o ExecutionActionOutput) LifecycleSubstate() pulumi.StringOutput {
	return o.ApplyT(func(v *ExecutionAction) pulumi.StringOutput { return v.LifecycleSubstate }).(pulumi.StringOutput)
}

// The current state of the execution action. Valid states are SCHEDULED, IN_PROGRESS, FAILED, CANCELED, UPDATING, DELETED, SUCCEEDED and PARTIAL_SUCCESS.
func (o ExecutionActionOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *ExecutionAction) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The date and time the execution action was created.
func (o ExecutionActionOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *ExecutionAction) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The last date and time that the execution action was updated.
func (o ExecutionActionOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *ExecutionAction) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

// The total time taken by corresponding resource activity in minutes.
func (o ExecutionActionOutput) TotalTimeTakenInMins() pulumi.IntOutput {
	return o.ApplyT(func(v *ExecutionAction) pulumi.IntOutput { return v.TotalTimeTakenInMins }).(pulumi.IntOutput)
}

type ExecutionActionArrayOutput struct{ *pulumi.OutputState }

func (ExecutionActionArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ExecutionAction)(nil)).Elem()
}

func (o ExecutionActionArrayOutput) ToExecutionActionArrayOutput() ExecutionActionArrayOutput {
	return o
}

func (o ExecutionActionArrayOutput) ToExecutionActionArrayOutputWithContext(ctx context.Context) ExecutionActionArrayOutput {
	return o
}

func (o ExecutionActionArrayOutput) Index(i pulumi.IntInput) ExecutionActionOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ExecutionAction {
		return vs[0].([]*ExecutionAction)[vs[1].(int)]
	}).(ExecutionActionOutput)
}

type ExecutionActionMapOutput struct{ *pulumi.OutputState }

func (ExecutionActionMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ExecutionAction)(nil)).Elem()
}

func (o ExecutionActionMapOutput) ToExecutionActionMapOutput() ExecutionActionMapOutput {
	return o
}

func (o ExecutionActionMapOutput) ToExecutionActionMapOutputWithContext(ctx context.Context) ExecutionActionMapOutput {
	return o
}

func (o ExecutionActionMapOutput) MapIndex(k pulumi.StringInput) ExecutionActionOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ExecutionAction {
		return vs[0].(map[string]*ExecutionAction)[vs[1].(string)]
	}).(ExecutionActionOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ExecutionActionInput)(nil)).Elem(), &ExecutionAction{})
	pulumi.RegisterInputType(reflect.TypeOf((*ExecutionActionArrayInput)(nil)).Elem(), ExecutionActionArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ExecutionActionMapInput)(nil)).Elem(), ExecutionActionMap{})
	pulumi.RegisterOutputType(ExecutionActionOutput{})
	pulumi.RegisterOutputType(ExecutionActionArrayOutput{})
	pulumi.RegisterOutputType(ExecutionActionMapOutput{})
}
