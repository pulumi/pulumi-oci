// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Alert resource in Oracle Cloud Infrastructure Data Safe service.
//
// Updates alert status of the specified alert.
//
// ## Import
//
// Alerts can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:DataSafe/alert:Alert test_alert "id"
//
// ```
type Alert struct {
	pulumi.CustomResourceState

	// The OCID of alert.
	AlertId pulumi.StringOutput `pulumi:"alertId"`
	// Type of the alert. Indicates the Data Safe feature triggering the alert.
	AlertType pulumi.StringOutput `pulumi:"alertType"`
	// (Updatable) A comment can be entered to track the alert changes done by the user.
	Comment pulumi.StringOutput `pulumi:"comment"`
	// (Updatable) The OCID of the compartment that contains the alert.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// The description of the alert.
	Description pulumi.StringOutput `pulumi:"description"`
	// The display name of the alert.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// Map that contains maps of values. Example: `{"Operations": {"CostCenter": "42"}}`
	FeatureDetails pulumi.MapOutput `pulumi:"featureDetails"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The operation (event) that triggered alert.
	Operation pulumi.StringOutput `pulumi:"operation"`
	// The result of the operation (event) that triggered alert.
	OperationStatus pulumi.StringOutput `pulumi:"operationStatus"`
	// Creation date and time of the operation that triggered alert, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	OperationTime pulumi.StringOutput `pulumi:"operationTime"`
	// The OCID of the policy that triggered alert.
	PolicyId pulumi.StringOutput `pulumi:"policyId"`
	// The resource endpoint that triggered the alert.
	ResourceName pulumi.StringOutput `pulumi:"resourceName"`
	// Severity level of the alert.
	Severity pulumi.StringOutput `pulumi:"severity"`
	// The current state of the alert.
	State pulumi.StringOutput `pulumi:"state"`
	// (Updatable) The status of the alert.
	Status pulumi.StringOutput `pulumi:"status"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// Array of OCIDs of the target database which are associated with the alert.
	TargetIds pulumi.StringArrayOutput `pulumi:"targetIds"`
	// Array of names of the target database.
	TargetNames pulumi.StringArrayOutput `pulumi:"targetNames"`
	// Creation date and time of the alert, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// Last date and time the alert was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewAlert registers a new resource with the given unique name, arguments, and options.
func NewAlert(ctx *pulumi.Context,
	name string, args *AlertArgs, opts ...pulumi.ResourceOption) (*Alert, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.AlertId == nil {
		return nil, errors.New("invalid value for required argument 'AlertId'")
	}
	var resource Alert
	err := ctx.RegisterResource("oci:DataSafe/alert:Alert", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetAlert gets an existing Alert resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetAlert(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *AlertState, opts ...pulumi.ResourceOption) (*Alert, error) {
	var resource Alert
	err := ctx.ReadResource("oci:DataSafe/alert:Alert", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Alert resources.
type alertState struct {
	// The OCID of alert.
	AlertId *string `pulumi:"alertId"`
	// Type of the alert. Indicates the Data Safe feature triggering the alert.
	AlertType *string `pulumi:"alertType"`
	// (Updatable) A comment can be entered to track the alert changes done by the user.
	Comment *string `pulumi:"comment"`
	// (Updatable) The OCID of the compartment that contains the alert.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The description of the alert.
	Description *string `pulumi:"description"`
	// The display name of the alert.
	DisplayName *string `pulumi:"displayName"`
	// Map that contains maps of values. Example: `{"Operations": {"CostCenter": "42"}}`
	FeatureDetails map[string]interface{} `pulumi:"featureDetails"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The operation (event) that triggered alert.
	Operation *string `pulumi:"operation"`
	// The result of the operation (event) that triggered alert.
	OperationStatus *string `pulumi:"operationStatus"`
	// Creation date and time of the operation that triggered alert, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	OperationTime *string `pulumi:"operationTime"`
	// The OCID of the policy that triggered alert.
	PolicyId *string `pulumi:"policyId"`
	// The resource endpoint that triggered the alert.
	ResourceName *string `pulumi:"resourceName"`
	// Severity level of the alert.
	Severity *string `pulumi:"severity"`
	// The current state of the alert.
	State *string `pulumi:"state"`
	// (Updatable) The status of the alert.
	Status *string `pulumi:"status"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// Array of OCIDs of the target database which are associated with the alert.
	TargetIds []string `pulumi:"targetIds"`
	// Array of names of the target database.
	TargetNames []string `pulumi:"targetNames"`
	// Creation date and time of the alert, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
	// Last date and time the alert was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type AlertState struct {
	// The OCID of alert.
	AlertId pulumi.StringPtrInput
	// Type of the alert. Indicates the Data Safe feature triggering the alert.
	AlertType pulumi.StringPtrInput
	// (Updatable) A comment can be entered to track the alert changes done by the user.
	Comment pulumi.StringPtrInput
	// (Updatable) The OCID of the compartment that contains the alert.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// The description of the alert.
	Description pulumi.StringPtrInput
	// The display name of the alert.
	DisplayName pulumi.StringPtrInput
	// Map that contains maps of values. Example: `{"Operations": {"CostCenter": "42"}}`
	FeatureDetails pulumi.MapInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The operation (event) that triggered alert.
	Operation pulumi.StringPtrInput
	// The result of the operation (event) that triggered alert.
	OperationStatus pulumi.StringPtrInput
	// Creation date and time of the operation that triggered alert, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	OperationTime pulumi.StringPtrInput
	// The OCID of the policy that triggered alert.
	PolicyId pulumi.StringPtrInput
	// The resource endpoint that triggered the alert.
	ResourceName pulumi.StringPtrInput
	// Severity level of the alert.
	Severity pulumi.StringPtrInput
	// The current state of the alert.
	State pulumi.StringPtrInput
	// (Updatable) The status of the alert.
	Status pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapInput
	// Array of OCIDs of the target database which are associated with the alert.
	TargetIds pulumi.StringArrayInput
	// Array of names of the target database.
	TargetNames pulumi.StringArrayInput
	// Creation date and time of the alert, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
	// Last date and time the alert was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeUpdated pulumi.StringPtrInput
}

func (AlertState) ElementType() reflect.Type {
	return reflect.TypeOf((*alertState)(nil)).Elem()
}

type alertArgs struct {
	// The OCID of alert.
	AlertId string `pulumi:"alertId"`
	// (Updatable) A comment can be entered to track the alert changes done by the user.
	Comment *string `pulumi:"comment"`
	// (Updatable) The OCID of the compartment that contains the alert.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) The status of the alert.
	Status *string `pulumi:"status"`
}

// The set of arguments for constructing a Alert resource.
type AlertArgs struct {
	// The OCID of alert.
	AlertId pulumi.StringInput
	// (Updatable) A comment can be entered to track the alert changes done by the user.
	Comment pulumi.StringPtrInput
	// (Updatable) The OCID of the compartment that contains the alert.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) The status of the alert.
	Status pulumi.StringPtrInput
}

func (AlertArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*alertArgs)(nil)).Elem()
}

type AlertInput interface {
	pulumi.Input

	ToAlertOutput() AlertOutput
	ToAlertOutputWithContext(ctx context.Context) AlertOutput
}

func (*Alert) ElementType() reflect.Type {
	return reflect.TypeOf((**Alert)(nil)).Elem()
}

func (i *Alert) ToAlertOutput() AlertOutput {
	return i.ToAlertOutputWithContext(context.Background())
}

func (i *Alert) ToAlertOutputWithContext(ctx context.Context) AlertOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AlertOutput)
}

// AlertArrayInput is an input type that accepts AlertArray and AlertArrayOutput values.
// You can construct a concrete instance of `AlertArrayInput` via:
//
//	AlertArray{ AlertArgs{...} }
type AlertArrayInput interface {
	pulumi.Input

	ToAlertArrayOutput() AlertArrayOutput
	ToAlertArrayOutputWithContext(context.Context) AlertArrayOutput
}

type AlertArray []AlertInput

func (AlertArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Alert)(nil)).Elem()
}

func (i AlertArray) ToAlertArrayOutput() AlertArrayOutput {
	return i.ToAlertArrayOutputWithContext(context.Background())
}

func (i AlertArray) ToAlertArrayOutputWithContext(ctx context.Context) AlertArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AlertArrayOutput)
}

// AlertMapInput is an input type that accepts AlertMap and AlertMapOutput values.
// You can construct a concrete instance of `AlertMapInput` via:
//
//	AlertMap{ "key": AlertArgs{...} }
type AlertMapInput interface {
	pulumi.Input

	ToAlertMapOutput() AlertMapOutput
	ToAlertMapOutputWithContext(context.Context) AlertMapOutput
}

type AlertMap map[string]AlertInput

func (AlertMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Alert)(nil)).Elem()
}

func (i AlertMap) ToAlertMapOutput() AlertMapOutput {
	return i.ToAlertMapOutputWithContext(context.Background())
}

func (i AlertMap) ToAlertMapOutputWithContext(ctx context.Context) AlertMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AlertMapOutput)
}

type AlertOutput struct{ *pulumi.OutputState }

func (AlertOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Alert)(nil)).Elem()
}

func (o AlertOutput) ToAlertOutput() AlertOutput {
	return o
}

func (o AlertOutput) ToAlertOutputWithContext(ctx context.Context) AlertOutput {
	return o
}

// The OCID of alert.
func (o AlertOutput) AlertId() pulumi.StringOutput {
	return o.ApplyT(func(v *Alert) pulumi.StringOutput { return v.AlertId }).(pulumi.StringOutput)
}

// Type of the alert. Indicates the Data Safe feature triggering the alert.
func (o AlertOutput) AlertType() pulumi.StringOutput {
	return o.ApplyT(func(v *Alert) pulumi.StringOutput { return v.AlertType }).(pulumi.StringOutput)
}

// (Updatable) A comment can be entered to track the alert changes done by the user.
func (o AlertOutput) Comment() pulumi.StringOutput {
	return o.ApplyT(func(v *Alert) pulumi.StringOutput { return v.Comment }).(pulumi.StringOutput)
}

// (Updatable) The OCID of the compartment that contains the alert.
func (o AlertOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Alert) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Operations.CostCenter": "42"}`
func (o AlertOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Alert) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// The description of the alert.
func (o AlertOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *Alert) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// The display name of the alert.
func (o AlertOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *Alert) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// Map that contains maps of values. Example: `{"Operations": {"CostCenter": "42"}}`
func (o AlertOutput) FeatureDetails() pulumi.MapOutput {
	return o.ApplyT(func(v *Alert) pulumi.MapOutput { return v.FeatureDetails }).(pulumi.MapOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{"Department": "Finance"}`
func (o AlertOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Alert) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// The operation (event) that triggered alert.
func (o AlertOutput) Operation() pulumi.StringOutput {
	return o.ApplyT(func(v *Alert) pulumi.StringOutput { return v.Operation }).(pulumi.StringOutput)
}

// The result of the operation (event) that triggered alert.
func (o AlertOutput) OperationStatus() pulumi.StringOutput {
	return o.ApplyT(func(v *Alert) pulumi.StringOutput { return v.OperationStatus }).(pulumi.StringOutput)
}

// Creation date and time of the operation that triggered alert, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o AlertOutput) OperationTime() pulumi.StringOutput {
	return o.ApplyT(func(v *Alert) pulumi.StringOutput { return v.OperationTime }).(pulumi.StringOutput)
}

// The OCID of the policy that triggered alert.
func (o AlertOutput) PolicyId() pulumi.StringOutput {
	return o.ApplyT(func(v *Alert) pulumi.StringOutput { return v.PolicyId }).(pulumi.StringOutput)
}

// The resource endpoint that triggered the alert.
func (o AlertOutput) ResourceName() pulumi.StringOutput {
	return o.ApplyT(func(v *Alert) pulumi.StringOutput { return v.ResourceName }).(pulumi.StringOutput)
}

// Severity level of the alert.
func (o AlertOutput) Severity() pulumi.StringOutput {
	return o.ApplyT(func(v *Alert) pulumi.StringOutput { return v.Severity }).(pulumi.StringOutput)
}

// The current state of the alert.
func (o AlertOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Alert) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// (Updatable) The status of the alert.
func (o AlertOutput) Status() pulumi.StringOutput {
	return o.ApplyT(func(v *Alert) pulumi.StringOutput { return v.Status }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o AlertOutput) SystemTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Alert) pulumi.MapOutput { return v.SystemTags }).(pulumi.MapOutput)
}

// Array of OCIDs of the target database which are associated with the alert.
func (o AlertOutput) TargetIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *Alert) pulumi.StringArrayOutput { return v.TargetIds }).(pulumi.StringArrayOutput)
}

// Array of names of the target database.
func (o AlertOutput) TargetNames() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *Alert) pulumi.StringArrayOutput { return v.TargetNames }).(pulumi.StringArrayOutput)
}

// Creation date and time of the alert, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o AlertOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *Alert) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// Last date and time the alert was updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o AlertOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *Alert) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type AlertArrayOutput struct{ *pulumi.OutputState }

func (AlertArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Alert)(nil)).Elem()
}

func (o AlertArrayOutput) ToAlertArrayOutput() AlertArrayOutput {
	return o
}

func (o AlertArrayOutput) ToAlertArrayOutputWithContext(ctx context.Context) AlertArrayOutput {
	return o
}

func (o AlertArrayOutput) Index(i pulumi.IntInput) AlertOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Alert {
		return vs[0].([]*Alert)[vs[1].(int)]
	}).(AlertOutput)
}

type AlertMapOutput struct{ *pulumi.OutputState }

func (AlertMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Alert)(nil)).Elem()
}

func (o AlertMapOutput) ToAlertMapOutput() AlertMapOutput {
	return o
}

func (o AlertMapOutput) ToAlertMapOutputWithContext(ctx context.Context) AlertMapOutput {
	return o
}

func (o AlertMapOutput) MapIndex(k pulumi.StringInput) AlertOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Alert {
		return vs[0].(map[string]*Alert)[vs[1].(string)]
	}).(AlertOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*AlertInput)(nil)).Elem(), &Alert{})
	pulumi.RegisterInputType(reflect.TypeOf((*AlertArrayInput)(nil)).Elem(), AlertArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*AlertMapInput)(nil)).Elem(), AlertMap{})
	pulumi.RegisterOutputType(AlertOutput{})
	pulumi.RegisterOutputType(AlertArrayOutput{})
	pulumi.RegisterOutputType(AlertMapOutput{})
}