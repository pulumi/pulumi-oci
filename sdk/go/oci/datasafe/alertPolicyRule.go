// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Alert Policy Rule resource in Oracle Cloud Infrastructure Data Safe service.
//
// Creates a new rule for the alert policy.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/datasafe"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := datasafe.NewAlertPolicyRule(ctx, "test_alert_policy_rule", &datasafe.AlertPolicyRuleArgs{
//				AlertPolicyId: pulumi.Any(testAlertPolicy.Id),
//				Expression:    pulumi.Any(alertPolicyRuleExpression),
//				Description:   pulumi.Any(alertPolicyRuleDescription),
//				DisplayName:   pulumi.Any(alertPolicyRuleDisplayName),
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
// AlertPolicyRules can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:DataSafe/alertPolicyRule:AlertPolicyRule test_alert_policy_rule "alertPolicies/{alertPolicyId}/rules/{ruleKey}"
// ```
type AlertPolicyRule struct {
	pulumi.CustomResourceState

	// The OCID of the alert policy.
	AlertPolicyId pulumi.StringOutput `pulumi:"alertPolicyId"`
	// (Updatable) Describes the alert policy rule.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) The display name of the alert policy rule.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) The conditional expression of the alert policy rule which evaluates to boolean value.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Expression pulumi.StringOutput `pulumi:"expression"`
	// The unique key of the alert policy rule.
	Key pulumi.StringOutput `pulumi:"key"`
	// The current state of the alert policy rule.
	State pulumi.StringOutput `pulumi:"state"`
	// Creation date and time of the alert policy rule, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
}

// NewAlertPolicyRule registers a new resource with the given unique name, arguments, and options.
func NewAlertPolicyRule(ctx *pulumi.Context,
	name string, args *AlertPolicyRuleArgs, opts ...pulumi.ResourceOption) (*AlertPolicyRule, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.AlertPolicyId == nil {
		return nil, errors.New("invalid value for required argument 'AlertPolicyId'")
	}
	if args.Expression == nil {
		return nil, errors.New("invalid value for required argument 'Expression'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource AlertPolicyRule
	err := ctx.RegisterResource("oci:DataSafe/alertPolicyRule:AlertPolicyRule", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetAlertPolicyRule gets an existing AlertPolicyRule resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetAlertPolicyRule(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *AlertPolicyRuleState, opts ...pulumi.ResourceOption) (*AlertPolicyRule, error) {
	var resource AlertPolicyRule
	err := ctx.ReadResource("oci:DataSafe/alertPolicyRule:AlertPolicyRule", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering AlertPolicyRule resources.
type alertPolicyRuleState struct {
	// The OCID of the alert policy.
	AlertPolicyId *string `pulumi:"alertPolicyId"`
	// (Updatable) Describes the alert policy rule.
	Description *string `pulumi:"description"`
	// (Updatable) The display name of the alert policy rule.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) The conditional expression of the alert policy rule which evaluates to boolean value.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Expression *string `pulumi:"expression"`
	// The unique key of the alert policy rule.
	Key *string `pulumi:"key"`
	// The current state of the alert policy rule.
	State *string `pulumi:"state"`
	// Creation date and time of the alert policy rule, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
}

type AlertPolicyRuleState struct {
	// The OCID of the alert policy.
	AlertPolicyId pulumi.StringPtrInput
	// (Updatable) Describes the alert policy rule.
	Description pulumi.StringPtrInput
	// (Updatable) The display name of the alert policy rule.
	DisplayName pulumi.StringPtrInput
	// (Updatable) The conditional expression of the alert policy rule which evaluates to boolean value.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Expression pulumi.StringPtrInput
	// The unique key of the alert policy rule.
	Key pulumi.StringPtrInput
	// The current state of the alert policy rule.
	State pulumi.StringPtrInput
	// Creation date and time of the alert policy rule, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
}

func (AlertPolicyRuleState) ElementType() reflect.Type {
	return reflect.TypeOf((*alertPolicyRuleState)(nil)).Elem()
}

type alertPolicyRuleArgs struct {
	// The OCID of the alert policy.
	AlertPolicyId string `pulumi:"alertPolicyId"`
	// (Updatable) Describes the alert policy rule.
	Description *string `pulumi:"description"`
	// (Updatable) The display name of the alert policy rule.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) The conditional expression of the alert policy rule which evaluates to boolean value.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Expression string `pulumi:"expression"`
}

// The set of arguments for constructing a AlertPolicyRule resource.
type AlertPolicyRuleArgs struct {
	// The OCID of the alert policy.
	AlertPolicyId pulumi.StringInput
	// (Updatable) Describes the alert policy rule.
	Description pulumi.StringPtrInput
	// (Updatable) The display name of the alert policy rule.
	DisplayName pulumi.StringPtrInput
	// (Updatable) The conditional expression of the alert policy rule which evaluates to boolean value.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Expression pulumi.StringInput
}

func (AlertPolicyRuleArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*alertPolicyRuleArgs)(nil)).Elem()
}

type AlertPolicyRuleInput interface {
	pulumi.Input

	ToAlertPolicyRuleOutput() AlertPolicyRuleOutput
	ToAlertPolicyRuleOutputWithContext(ctx context.Context) AlertPolicyRuleOutput
}

func (*AlertPolicyRule) ElementType() reflect.Type {
	return reflect.TypeOf((**AlertPolicyRule)(nil)).Elem()
}

func (i *AlertPolicyRule) ToAlertPolicyRuleOutput() AlertPolicyRuleOutput {
	return i.ToAlertPolicyRuleOutputWithContext(context.Background())
}

func (i *AlertPolicyRule) ToAlertPolicyRuleOutputWithContext(ctx context.Context) AlertPolicyRuleOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AlertPolicyRuleOutput)
}

// AlertPolicyRuleArrayInput is an input type that accepts AlertPolicyRuleArray and AlertPolicyRuleArrayOutput values.
// You can construct a concrete instance of `AlertPolicyRuleArrayInput` via:
//
//	AlertPolicyRuleArray{ AlertPolicyRuleArgs{...} }
type AlertPolicyRuleArrayInput interface {
	pulumi.Input

	ToAlertPolicyRuleArrayOutput() AlertPolicyRuleArrayOutput
	ToAlertPolicyRuleArrayOutputWithContext(context.Context) AlertPolicyRuleArrayOutput
}

type AlertPolicyRuleArray []AlertPolicyRuleInput

func (AlertPolicyRuleArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*AlertPolicyRule)(nil)).Elem()
}

func (i AlertPolicyRuleArray) ToAlertPolicyRuleArrayOutput() AlertPolicyRuleArrayOutput {
	return i.ToAlertPolicyRuleArrayOutputWithContext(context.Background())
}

func (i AlertPolicyRuleArray) ToAlertPolicyRuleArrayOutputWithContext(ctx context.Context) AlertPolicyRuleArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AlertPolicyRuleArrayOutput)
}

// AlertPolicyRuleMapInput is an input type that accepts AlertPolicyRuleMap and AlertPolicyRuleMapOutput values.
// You can construct a concrete instance of `AlertPolicyRuleMapInput` via:
//
//	AlertPolicyRuleMap{ "key": AlertPolicyRuleArgs{...} }
type AlertPolicyRuleMapInput interface {
	pulumi.Input

	ToAlertPolicyRuleMapOutput() AlertPolicyRuleMapOutput
	ToAlertPolicyRuleMapOutputWithContext(context.Context) AlertPolicyRuleMapOutput
}

type AlertPolicyRuleMap map[string]AlertPolicyRuleInput

func (AlertPolicyRuleMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*AlertPolicyRule)(nil)).Elem()
}

func (i AlertPolicyRuleMap) ToAlertPolicyRuleMapOutput() AlertPolicyRuleMapOutput {
	return i.ToAlertPolicyRuleMapOutputWithContext(context.Background())
}

func (i AlertPolicyRuleMap) ToAlertPolicyRuleMapOutputWithContext(ctx context.Context) AlertPolicyRuleMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AlertPolicyRuleMapOutput)
}

type AlertPolicyRuleOutput struct{ *pulumi.OutputState }

func (AlertPolicyRuleOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**AlertPolicyRule)(nil)).Elem()
}

func (o AlertPolicyRuleOutput) ToAlertPolicyRuleOutput() AlertPolicyRuleOutput {
	return o
}

func (o AlertPolicyRuleOutput) ToAlertPolicyRuleOutputWithContext(ctx context.Context) AlertPolicyRuleOutput {
	return o
}

// The OCID of the alert policy.
func (o AlertPolicyRuleOutput) AlertPolicyId() pulumi.StringOutput {
	return o.ApplyT(func(v *AlertPolicyRule) pulumi.StringOutput { return v.AlertPolicyId }).(pulumi.StringOutput)
}

// (Updatable) Describes the alert policy rule.
func (o AlertPolicyRuleOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *AlertPolicyRule) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) The display name of the alert policy rule.
func (o AlertPolicyRuleOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *AlertPolicyRule) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) The conditional expression of the alert policy rule which evaluates to boolean value.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o AlertPolicyRuleOutput) Expression() pulumi.StringOutput {
	return o.ApplyT(func(v *AlertPolicyRule) pulumi.StringOutput { return v.Expression }).(pulumi.StringOutput)
}

// The unique key of the alert policy rule.
func (o AlertPolicyRuleOutput) Key() pulumi.StringOutput {
	return o.ApplyT(func(v *AlertPolicyRule) pulumi.StringOutput { return v.Key }).(pulumi.StringOutput)
}

// The current state of the alert policy rule.
func (o AlertPolicyRuleOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *AlertPolicyRule) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Creation date and time of the alert policy rule, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o AlertPolicyRuleOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *AlertPolicyRule) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

type AlertPolicyRuleArrayOutput struct{ *pulumi.OutputState }

func (AlertPolicyRuleArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*AlertPolicyRule)(nil)).Elem()
}

func (o AlertPolicyRuleArrayOutput) ToAlertPolicyRuleArrayOutput() AlertPolicyRuleArrayOutput {
	return o
}

func (o AlertPolicyRuleArrayOutput) ToAlertPolicyRuleArrayOutputWithContext(ctx context.Context) AlertPolicyRuleArrayOutput {
	return o
}

func (o AlertPolicyRuleArrayOutput) Index(i pulumi.IntInput) AlertPolicyRuleOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *AlertPolicyRule {
		return vs[0].([]*AlertPolicyRule)[vs[1].(int)]
	}).(AlertPolicyRuleOutput)
}

type AlertPolicyRuleMapOutput struct{ *pulumi.OutputState }

func (AlertPolicyRuleMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*AlertPolicyRule)(nil)).Elem()
}

func (o AlertPolicyRuleMapOutput) ToAlertPolicyRuleMapOutput() AlertPolicyRuleMapOutput {
	return o
}

func (o AlertPolicyRuleMapOutput) ToAlertPolicyRuleMapOutputWithContext(ctx context.Context) AlertPolicyRuleMapOutput {
	return o
}

func (o AlertPolicyRuleMapOutput) MapIndex(k pulumi.StringInput) AlertPolicyRuleOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *AlertPolicyRule {
		return vs[0].(map[string]*AlertPolicyRule)[vs[1].(string)]
	}).(AlertPolicyRuleOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*AlertPolicyRuleInput)(nil)).Elem(), &AlertPolicyRule{})
	pulumi.RegisterInputType(reflect.TypeOf((*AlertPolicyRuleArrayInput)(nil)).Elem(), AlertPolicyRuleArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*AlertPolicyRuleMapInput)(nil)).Elem(), AlertPolicyRuleMap{})
	pulumi.RegisterOutputType(AlertPolicyRuleOutput{})
	pulumi.RegisterOutputType(AlertPolicyRuleArrayOutput{})
	pulumi.RegisterOutputType(AlertPolicyRuleMapOutput{})
}
