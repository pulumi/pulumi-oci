// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package loadbalancer

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Rule Set resource in Oracle Cloud Infrastructure Load Balancer service.
//
// Creates a new rule set associated with the specified load balancer. For more information, see
// [Managing Rule Sets](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrulesets.htm).
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/loadbalancer"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := loadbalancer.NewRuleSet(ctx, "test_rule_set", &loadbalancer.RuleSetArgs{
//				Items: loadbalancer.RuleSetItemArray{
//					&loadbalancer.RuleSetItemArgs{
//						Action:                      pulumi.Any(ruleSetItemsAction),
//						AllowedMethods:              pulumi.Any(ruleSetItemsAllowedMethods),
//						AreInvalidCharactersAllowed: pulumi.Any(ruleSetItemsAreInvalidCharactersAllowed),
//						Conditions: loadbalancer.RuleSetItemConditionArray{
//							&loadbalancer.RuleSetItemConditionArgs{
//								AttributeName:  pulumi.Any(ruleSetItemsConditionsAttributeName),
//								AttributeValue: pulumi.Any(ruleSetItemsConditionsAttributeValue),
//								Operator:       pulumi.Any(ruleSetItemsConditionsOperator),
//							},
//						},
//						DefaultMaxConnections:   pulumi.Any(ruleSetItemsDefaultMaxConnections),
//						Description:             pulumi.Any(ruleSetItemsDescription),
//						Header:                  pulumi.Any(ruleSetItemsHeader),
//						HttpLargeHeaderSizeInKb: pulumi.Any(ruleSetItemsHttpLargeHeaderSizeInKb),
//						IpMaxConnections: loadbalancer.RuleSetItemIpMaxConnectionArray{
//							&loadbalancer.RuleSetItemIpMaxConnectionArgs{
//								IpAddresses:    pulumi.Any(ruleSetItemsIpMaxConnectionsIpAddresses),
//								MaxConnections: pulumi.Any(ruleSetItemsIpMaxConnectionsMaxConnections),
//							},
//						},
//						Prefix: pulumi.Any(ruleSetItemsPrefix),
//						RedirectUri: &loadbalancer.RuleSetItemRedirectUriArgs{
//							Host:     pulumi.Any(ruleSetItemsRedirectUriHost),
//							Path:     pulumi.Any(ruleSetItemsRedirectUriPath),
//							Port:     pulumi.Any(ruleSetItemsRedirectUriPort),
//							Protocol: pulumi.Any(ruleSetItemsRedirectUriProtocol),
//							Query:    pulumi.Any(ruleSetItemsRedirectUriQuery),
//						},
//						ResponseCode: pulumi.Any(ruleSetItemsResponseCode),
//						StatusCode:   pulumi.Any(ruleSetItemsStatusCode),
//						Suffix:       pulumi.Any(ruleSetItemsSuffix),
//						Value:        pulumi.Any(ruleSetItemsValue),
//					},
//				},
//				LoadBalancerId: pulumi.Any(testLoadBalancer.Id),
//				Name:           pulumi.Any(ruleSetName),
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
// RuleSets can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:LoadBalancer/ruleSet:RuleSet test_rule_set "loadBalancers/{loadBalancerId}/ruleSets/{ruleSetName}"
// ```
type RuleSet struct {
	pulumi.CustomResourceState

	// (Updatable) An array of rules that compose the rule set. For more information, see [Managing Rule Sets](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrulesets.htm)
	Items RuleSetItemArrayOutput `pulumi:"items"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
	LoadBalancerId pulumi.StringOutput `pulumi:"loadBalancerId"`
	// The name for this set of rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `exampleRuleSet`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Name  pulumi.StringOutput `pulumi:"name"`
	State pulumi.StringOutput `pulumi:"state"`
}

// NewRuleSet registers a new resource with the given unique name, arguments, and options.
func NewRuleSet(ctx *pulumi.Context,
	name string, args *RuleSetArgs, opts ...pulumi.ResourceOption) (*RuleSet, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.Items == nil {
		return nil, errors.New("invalid value for required argument 'Items'")
	}
	if args.LoadBalancerId == nil {
		return nil, errors.New("invalid value for required argument 'LoadBalancerId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource RuleSet
	err := ctx.RegisterResource("oci:LoadBalancer/ruleSet:RuleSet", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetRuleSet gets an existing RuleSet resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetRuleSet(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *RuleSetState, opts ...pulumi.ResourceOption) (*RuleSet, error) {
	var resource RuleSet
	err := ctx.ReadResource("oci:LoadBalancer/ruleSet:RuleSet", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering RuleSet resources.
type ruleSetState struct {
	// (Updatable) An array of rules that compose the rule set. For more information, see [Managing Rule Sets](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrulesets.htm)
	Items []RuleSetItem `pulumi:"items"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
	LoadBalancerId *string `pulumi:"loadBalancerId"`
	// The name for this set of rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `exampleRuleSet`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Name  *string `pulumi:"name"`
	State *string `pulumi:"state"`
}

type RuleSetState struct {
	// (Updatable) An array of rules that compose the rule set. For more information, see [Managing Rule Sets](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrulesets.htm)
	Items RuleSetItemArrayInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
	LoadBalancerId pulumi.StringPtrInput
	// The name for this set of rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `exampleRuleSet`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Name  pulumi.StringPtrInput
	State pulumi.StringPtrInput
}

func (RuleSetState) ElementType() reflect.Type {
	return reflect.TypeOf((*ruleSetState)(nil)).Elem()
}

type ruleSetArgs struct {
	// (Updatable) An array of rules that compose the rule set. For more information, see [Managing Rule Sets](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrulesets.htm)
	Items []RuleSetItem `pulumi:"items"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
	LoadBalancerId string `pulumi:"loadBalancerId"`
	// The name for this set of rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `exampleRuleSet`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Name *string `pulumi:"name"`
}

// The set of arguments for constructing a RuleSet resource.
type RuleSetArgs struct {
	// (Updatable) An array of rules that compose the rule set. For more information, see [Managing Rule Sets](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrulesets.htm)
	Items RuleSetItemArrayInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
	LoadBalancerId pulumi.StringInput
	// The name for this set of rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `exampleRuleSet`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Name pulumi.StringPtrInput
}

func (RuleSetArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*ruleSetArgs)(nil)).Elem()
}

type RuleSetInput interface {
	pulumi.Input

	ToRuleSetOutput() RuleSetOutput
	ToRuleSetOutputWithContext(ctx context.Context) RuleSetOutput
}

func (*RuleSet) ElementType() reflect.Type {
	return reflect.TypeOf((**RuleSet)(nil)).Elem()
}

func (i *RuleSet) ToRuleSetOutput() RuleSetOutput {
	return i.ToRuleSetOutputWithContext(context.Background())
}

func (i *RuleSet) ToRuleSetOutputWithContext(ctx context.Context) RuleSetOutput {
	return pulumi.ToOutputWithContext(ctx, i).(RuleSetOutput)
}

// RuleSetArrayInput is an input type that accepts RuleSetArray and RuleSetArrayOutput values.
// You can construct a concrete instance of `RuleSetArrayInput` via:
//
//	RuleSetArray{ RuleSetArgs{...} }
type RuleSetArrayInput interface {
	pulumi.Input

	ToRuleSetArrayOutput() RuleSetArrayOutput
	ToRuleSetArrayOutputWithContext(context.Context) RuleSetArrayOutput
}

type RuleSetArray []RuleSetInput

func (RuleSetArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*RuleSet)(nil)).Elem()
}

func (i RuleSetArray) ToRuleSetArrayOutput() RuleSetArrayOutput {
	return i.ToRuleSetArrayOutputWithContext(context.Background())
}

func (i RuleSetArray) ToRuleSetArrayOutputWithContext(ctx context.Context) RuleSetArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(RuleSetArrayOutput)
}

// RuleSetMapInput is an input type that accepts RuleSetMap and RuleSetMapOutput values.
// You can construct a concrete instance of `RuleSetMapInput` via:
//
//	RuleSetMap{ "key": RuleSetArgs{...} }
type RuleSetMapInput interface {
	pulumi.Input

	ToRuleSetMapOutput() RuleSetMapOutput
	ToRuleSetMapOutputWithContext(context.Context) RuleSetMapOutput
}

type RuleSetMap map[string]RuleSetInput

func (RuleSetMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*RuleSet)(nil)).Elem()
}

func (i RuleSetMap) ToRuleSetMapOutput() RuleSetMapOutput {
	return i.ToRuleSetMapOutputWithContext(context.Background())
}

func (i RuleSetMap) ToRuleSetMapOutputWithContext(ctx context.Context) RuleSetMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(RuleSetMapOutput)
}

type RuleSetOutput struct{ *pulumi.OutputState }

func (RuleSetOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**RuleSet)(nil)).Elem()
}

func (o RuleSetOutput) ToRuleSetOutput() RuleSetOutput {
	return o
}

func (o RuleSetOutput) ToRuleSetOutputWithContext(ctx context.Context) RuleSetOutput {
	return o
}

// (Updatable) An array of rules that compose the rule set. For more information, see [Managing Rule Sets](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrulesets.htm)
func (o RuleSetOutput) Items() RuleSetItemArrayOutput {
	return o.ApplyT(func(v *RuleSet) RuleSetItemArrayOutput { return v.Items }).(RuleSetItemArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the specified load balancer.
func (o RuleSetOutput) LoadBalancerId() pulumi.StringOutput {
	return o.ApplyT(func(v *RuleSet) pulumi.StringOutput { return v.LoadBalancerId }).(pulumi.StringOutput)
}

// The name for this set of rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `exampleRuleSet`
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o RuleSetOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *RuleSet) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

func (o RuleSetOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *RuleSet) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

type RuleSetArrayOutput struct{ *pulumi.OutputState }

func (RuleSetArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*RuleSet)(nil)).Elem()
}

func (o RuleSetArrayOutput) ToRuleSetArrayOutput() RuleSetArrayOutput {
	return o
}

func (o RuleSetArrayOutput) ToRuleSetArrayOutputWithContext(ctx context.Context) RuleSetArrayOutput {
	return o
}

func (o RuleSetArrayOutput) Index(i pulumi.IntInput) RuleSetOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *RuleSet {
		return vs[0].([]*RuleSet)[vs[1].(int)]
	}).(RuleSetOutput)
}

type RuleSetMapOutput struct{ *pulumi.OutputState }

func (RuleSetMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*RuleSet)(nil)).Elem()
}

func (o RuleSetMapOutput) ToRuleSetMapOutput() RuleSetMapOutput {
	return o
}

func (o RuleSetMapOutput) ToRuleSetMapOutputWithContext(ctx context.Context) RuleSetMapOutput {
	return o
}

func (o RuleSetMapOutput) MapIndex(k pulumi.StringInput) RuleSetOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *RuleSet {
		return vs[0].(map[string]*RuleSet)[vs[1].(string)]
	}).(RuleSetOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*RuleSetInput)(nil)).Elem(), &RuleSet{})
	pulumi.RegisterInputType(reflect.TypeOf((*RuleSetArrayInput)(nil)).Elem(), RuleSetArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*RuleSetMapInput)(nil)).Elem(), RuleSetMap{})
	pulumi.RegisterOutputType(RuleSetOutput{})
	pulumi.RegisterOutputType(RuleSetArrayOutput{})
	pulumi.RegisterOutputType(RuleSetMapOutput{})
}
