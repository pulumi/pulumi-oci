// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package waas

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Protection Rule resource in Oracle Cloud Infrastructure Web Application Acceleration and Security service.
//
// Updates the action for each specified protection rule. Requests can either be allowed, blocked, or trigger an alert if they meet the parameters of an applied rule. For more information on protection rules, see [WAF Protection Rules](https://docs.cloud.oracle.com/iaas/Content/WAF/Tasks/wafprotectionrules.htm).
// This operation can update or disable protection rules depending on the structure of the request body.
// Protection rules can be updated by changing the properties of the protection rule object with the rule's key specified in the key field.
//
// ## Import
//
// ProtectionRules can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:Waas/protectionRule:ProtectionRule test_protection_rule "waasPolicyId/{waasPolicyId}/key/{key}"
// ```
type ProtectionRule struct {
	pulumi.CustomResourceState

	// (Updatable) The action to take when the traffic is detected as malicious. If unspecified, defaults to `OFF`.
	Action pulumi.StringOutput `pulumi:"action"`
	// The description of the protection rule.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable)
	Exclusions ProtectionRuleExclusionArrayOutput `pulumi:"exclusions"`
	// (Updatable) The unique key of the protection rule.
	Key pulumi.StringOutput `pulumi:"key"`
	// The list of labels for the protection rule.
	Labels pulumi.StringArrayOutput `pulumi:"labels"`
	// The list of the ModSecurity rule IDs that apply to this protection rule. For more information about ModSecurity's open source WAF rules, see [Mod Security's documentation](https://www.modsecurity.org/CRS/Documentation/index.html).
	ModSecurityRuleIds pulumi.StringArrayOutput `pulumi:"modSecurityRuleIds"`
	// The name of the protection rule.
	Name pulumi.StringOutput `pulumi:"name"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
	WaasPolicyId pulumi.StringOutput `pulumi:"waasPolicyId"`
}

// NewProtectionRule registers a new resource with the given unique name, arguments, and options.
func NewProtectionRule(ctx *pulumi.Context,
	name string, args *ProtectionRuleArgs, opts ...pulumi.ResourceOption) (*ProtectionRule, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Key == nil {
		return nil, errors.New("invalid value for required argument 'Key'")
	}
	if args.WaasPolicyId == nil {
		return nil, errors.New("invalid value for required argument 'WaasPolicyId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource ProtectionRule
	err := ctx.RegisterResource("oci:Waas/protectionRule:ProtectionRule", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetProtectionRule gets an existing ProtectionRule resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetProtectionRule(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ProtectionRuleState, opts ...pulumi.ResourceOption) (*ProtectionRule, error) {
	var resource ProtectionRule
	err := ctx.ReadResource("oci:Waas/protectionRule:ProtectionRule", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering ProtectionRule resources.
type protectionRuleState struct {
	// (Updatable) The action to take when the traffic is detected as malicious. If unspecified, defaults to `OFF`.
	Action *string `pulumi:"action"`
	// The description of the protection rule.
	Description *string `pulumi:"description"`
	// (Updatable)
	Exclusions []ProtectionRuleExclusion `pulumi:"exclusions"`
	// (Updatable) The unique key of the protection rule.
	Key *string `pulumi:"key"`
	// The list of labels for the protection rule.
	Labels []string `pulumi:"labels"`
	// The list of the ModSecurity rule IDs that apply to this protection rule. For more information about ModSecurity's open source WAF rules, see [Mod Security's documentation](https://www.modsecurity.org/CRS/Documentation/index.html).
	ModSecurityRuleIds []string `pulumi:"modSecurityRuleIds"`
	// The name of the protection rule.
	Name *string `pulumi:"name"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
	WaasPolicyId *string `pulumi:"waasPolicyId"`
}

type ProtectionRuleState struct {
	// (Updatable) The action to take when the traffic is detected as malicious. If unspecified, defaults to `OFF`.
	Action pulumi.StringPtrInput
	// The description of the protection rule.
	Description pulumi.StringPtrInput
	// (Updatable)
	Exclusions ProtectionRuleExclusionArrayInput
	// (Updatable) The unique key of the protection rule.
	Key pulumi.StringPtrInput
	// The list of labels for the protection rule.
	Labels pulumi.StringArrayInput
	// The list of the ModSecurity rule IDs that apply to this protection rule. For more information about ModSecurity's open source WAF rules, see [Mod Security's documentation](https://www.modsecurity.org/CRS/Documentation/index.html).
	ModSecurityRuleIds pulumi.StringArrayInput
	// The name of the protection rule.
	Name pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
	WaasPolicyId pulumi.StringPtrInput
}

func (ProtectionRuleState) ElementType() reflect.Type {
	return reflect.TypeOf((*protectionRuleState)(nil)).Elem()
}

type protectionRuleArgs struct {
	// (Updatable) The action to take when the traffic is detected as malicious. If unspecified, defaults to `OFF`.
	Action *string `pulumi:"action"`
	// (Updatable)
	Exclusions []ProtectionRuleExclusion `pulumi:"exclusions"`
	// (Updatable) The unique key of the protection rule.
	Key string `pulumi:"key"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
	WaasPolicyId string `pulumi:"waasPolicyId"`
}

// The set of arguments for constructing a ProtectionRule resource.
type ProtectionRuleArgs struct {
	// (Updatable) The action to take when the traffic is detected as malicious. If unspecified, defaults to `OFF`.
	Action pulumi.StringPtrInput
	// (Updatable)
	Exclusions ProtectionRuleExclusionArrayInput
	// (Updatable) The unique key of the protection rule.
	Key pulumi.StringInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
	WaasPolicyId pulumi.StringInput
}

func (ProtectionRuleArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*protectionRuleArgs)(nil)).Elem()
}

type ProtectionRuleInput interface {
	pulumi.Input

	ToProtectionRuleOutput() ProtectionRuleOutput
	ToProtectionRuleOutputWithContext(ctx context.Context) ProtectionRuleOutput
}

func (*ProtectionRule) ElementType() reflect.Type {
	return reflect.TypeOf((**ProtectionRule)(nil)).Elem()
}

func (i *ProtectionRule) ToProtectionRuleOutput() ProtectionRuleOutput {
	return i.ToProtectionRuleOutputWithContext(context.Background())
}

func (i *ProtectionRule) ToProtectionRuleOutputWithContext(ctx context.Context) ProtectionRuleOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ProtectionRuleOutput)
}

// ProtectionRuleArrayInput is an input type that accepts ProtectionRuleArray and ProtectionRuleArrayOutput values.
// You can construct a concrete instance of `ProtectionRuleArrayInput` via:
//
//	ProtectionRuleArray{ ProtectionRuleArgs{...} }
type ProtectionRuleArrayInput interface {
	pulumi.Input

	ToProtectionRuleArrayOutput() ProtectionRuleArrayOutput
	ToProtectionRuleArrayOutputWithContext(context.Context) ProtectionRuleArrayOutput
}

type ProtectionRuleArray []ProtectionRuleInput

func (ProtectionRuleArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ProtectionRule)(nil)).Elem()
}

func (i ProtectionRuleArray) ToProtectionRuleArrayOutput() ProtectionRuleArrayOutput {
	return i.ToProtectionRuleArrayOutputWithContext(context.Background())
}

func (i ProtectionRuleArray) ToProtectionRuleArrayOutputWithContext(ctx context.Context) ProtectionRuleArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ProtectionRuleArrayOutput)
}

// ProtectionRuleMapInput is an input type that accepts ProtectionRuleMap and ProtectionRuleMapOutput values.
// You can construct a concrete instance of `ProtectionRuleMapInput` via:
//
//	ProtectionRuleMap{ "key": ProtectionRuleArgs{...} }
type ProtectionRuleMapInput interface {
	pulumi.Input

	ToProtectionRuleMapOutput() ProtectionRuleMapOutput
	ToProtectionRuleMapOutputWithContext(context.Context) ProtectionRuleMapOutput
}

type ProtectionRuleMap map[string]ProtectionRuleInput

func (ProtectionRuleMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ProtectionRule)(nil)).Elem()
}

func (i ProtectionRuleMap) ToProtectionRuleMapOutput() ProtectionRuleMapOutput {
	return i.ToProtectionRuleMapOutputWithContext(context.Background())
}

func (i ProtectionRuleMap) ToProtectionRuleMapOutputWithContext(ctx context.Context) ProtectionRuleMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ProtectionRuleMapOutput)
}

type ProtectionRuleOutput struct{ *pulumi.OutputState }

func (ProtectionRuleOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**ProtectionRule)(nil)).Elem()
}

func (o ProtectionRuleOutput) ToProtectionRuleOutput() ProtectionRuleOutput {
	return o
}

func (o ProtectionRuleOutput) ToProtectionRuleOutputWithContext(ctx context.Context) ProtectionRuleOutput {
	return o
}

// (Updatable) The action to take when the traffic is detected as malicious. If unspecified, defaults to `OFF`.
func (o ProtectionRuleOutput) Action() pulumi.StringOutput {
	return o.ApplyT(func(v *ProtectionRule) pulumi.StringOutput { return v.Action }).(pulumi.StringOutput)
}

// The description of the protection rule.
func (o ProtectionRuleOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *ProtectionRule) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable)
func (o ProtectionRuleOutput) Exclusions() ProtectionRuleExclusionArrayOutput {
	return o.ApplyT(func(v *ProtectionRule) ProtectionRuleExclusionArrayOutput { return v.Exclusions }).(ProtectionRuleExclusionArrayOutput)
}

// (Updatable) The unique key of the protection rule.
func (o ProtectionRuleOutput) Key() pulumi.StringOutput {
	return o.ApplyT(func(v *ProtectionRule) pulumi.StringOutput { return v.Key }).(pulumi.StringOutput)
}

// The list of labels for the protection rule.
func (o ProtectionRuleOutput) Labels() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *ProtectionRule) pulumi.StringArrayOutput { return v.Labels }).(pulumi.StringArrayOutput)
}

// The list of the ModSecurity rule IDs that apply to this protection rule. For more information about ModSecurity's open source WAF rules, see [Mod Security's documentation](https://www.modsecurity.org/CRS/Documentation/index.html).
func (o ProtectionRuleOutput) ModSecurityRuleIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *ProtectionRule) pulumi.StringArrayOutput { return v.ModSecurityRuleIds }).(pulumi.StringArrayOutput)
}

// The name of the protection rule.
func (o ProtectionRuleOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *ProtectionRule) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WAAS policy.
func (o ProtectionRuleOutput) WaasPolicyId() pulumi.StringOutput {
	return o.ApplyT(func(v *ProtectionRule) pulumi.StringOutput { return v.WaasPolicyId }).(pulumi.StringOutput)
}

type ProtectionRuleArrayOutput struct{ *pulumi.OutputState }

func (ProtectionRuleArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*ProtectionRule)(nil)).Elem()
}

func (o ProtectionRuleArrayOutput) ToProtectionRuleArrayOutput() ProtectionRuleArrayOutput {
	return o
}

func (o ProtectionRuleArrayOutput) ToProtectionRuleArrayOutputWithContext(ctx context.Context) ProtectionRuleArrayOutput {
	return o
}

func (o ProtectionRuleArrayOutput) Index(i pulumi.IntInput) ProtectionRuleOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *ProtectionRule {
		return vs[0].([]*ProtectionRule)[vs[1].(int)]
	}).(ProtectionRuleOutput)
}

type ProtectionRuleMapOutput struct{ *pulumi.OutputState }

func (ProtectionRuleMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*ProtectionRule)(nil)).Elem()
}

func (o ProtectionRuleMapOutput) ToProtectionRuleMapOutput() ProtectionRuleMapOutput {
	return o
}

func (o ProtectionRuleMapOutput) ToProtectionRuleMapOutputWithContext(ctx context.Context) ProtectionRuleMapOutput {
	return o
}

func (o ProtectionRuleMapOutput) MapIndex(k pulumi.StringInput) ProtectionRuleOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *ProtectionRule {
		return vs[0].(map[string]*ProtectionRule)[vs[1].(string)]
	}).(ProtectionRuleOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ProtectionRuleInput)(nil)).Elem(), &ProtectionRule{})
	pulumi.RegisterInputType(reflect.TypeOf((*ProtectionRuleArrayInput)(nil)).Elem(), ProtectionRuleArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ProtectionRuleMapInput)(nil)).Elem(), ProtectionRuleMap{})
	pulumi.RegisterOutputType(ProtectionRuleOutput{})
	pulumi.RegisterOutputType(ProtectionRuleArrayOutput{})
	pulumi.RegisterOutputType(ProtectionRuleMapOutput{})
}
