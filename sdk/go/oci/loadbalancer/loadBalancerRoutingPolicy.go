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

// This resource provides the Load Balancer Routing Policy resource in Oracle Cloud Infrastructure Load Balancer service.
//
// Adds a routing policy to a load balancer. For more information, see
// [Managing Request Routing](https://docs.cloud.oracle.com/iaas/Content/Balance/Tasks/managingrequest.htm).
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
//			_, err := loadbalancer.NewLoadBalancerRoutingPolicy(ctx, "test_load_balancer_routing_policy", &loadbalancer.LoadBalancerRoutingPolicyArgs{
//				ConditionLanguageVersion: pulumi.Any(loadBalancerRoutingPolicyConditionLanguageVersion),
//				LoadBalancerId:           pulumi.Any(testLoadBalancer.Id),
//				Name:                     pulumi.Any(loadBalancerRoutingPolicyName),
//				Rules: loadbalancer.LoadBalancerRoutingPolicyRuleArray{
//					&loadbalancer.LoadBalancerRoutingPolicyRuleArgs{
//						Actions: loadbalancer.LoadBalancerRoutingPolicyRuleActionArray{
//							&loadbalancer.LoadBalancerRoutingPolicyRuleActionArgs{
//								BackendSetName: pulumi.Any(testBackendSet.Name),
//								Name:           pulumi.Any(loadBalancerRoutingPolicyRulesActionsName),
//							},
//						},
//						Condition: pulumi.Any(loadBalancerRoutingPolicyRulesCondition),
//						Name:      pulumi.Any(loadBalancerRoutingPolicyRulesName),
//					},
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
// LoadBalancerRoutingPolicies can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:LoadBalancer/loadBalancerRoutingPolicy:LoadBalancerRoutingPolicy test_load_balancer_routing_policy "loadBalancers/{loadBalancerId}/routingPolicies/{routingPolicyName}"
// ```
type LoadBalancerRoutingPolicy struct {
	pulumi.CustomResourceState

	// (Updatable) The version of the language in which `condition` of `rules` are composed.
	ConditionLanguageVersion pulumi.StringOutput `pulumi:"conditionLanguageVersion"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the routing policy rule list to.
	LoadBalancerId pulumi.StringOutput `pulumi:"loadBalancerId"`
	// The name for this list of routing rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `exampleRoutingRules`
	Name pulumi.StringOutput `pulumi:"name"`
	// (Updatable) The list of routing rules.
	Rules LoadBalancerRoutingPolicyRuleArrayOutput `pulumi:"rules"`
	State pulumi.StringOutput                      `pulumi:"state"`
}

// NewLoadBalancerRoutingPolicy registers a new resource with the given unique name, arguments, and options.
func NewLoadBalancerRoutingPolicy(ctx *pulumi.Context,
	name string, args *LoadBalancerRoutingPolicyArgs, opts ...pulumi.ResourceOption) (*LoadBalancerRoutingPolicy, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.ConditionLanguageVersion == nil {
		return nil, errors.New("invalid value for required argument 'ConditionLanguageVersion'")
	}
	if args.LoadBalancerId == nil {
		return nil, errors.New("invalid value for required argument 'LoadBalancerId'")
	}
	if args.Rules == nil {
		return nil, errors.New("invalid value for required argument 'Rules'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource LoadBalancerRoutingPolicy
	err := ctx.RegisterResource("oci:LoadBalancer/loadBalancerRoutingPolicy:LoadBalancerRoutingPolicy", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetLoadBalancerRoutingPolicy gets an existing LoadBalancerRoutingPolicy resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetLoadBalancerRoutingPolicy(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *LoadBalancerRoutingPolicyState, opts ...pulumi.ResourceOption) (*LoadBalancerRoutingPolicy, error) {
	var resource LoadBalancerRoutingPolicy
	err := ctx.ReadResource("oci:LoadBalancer/loadBalancerRoutingPolicy:LoadBalancerRoutingPolicy", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering LoadBalancerRoutingPolicy resources.
type loadBalancerRoutingPolicyState struct {
	// (Updatable) The version of the language in which `condition` of `rules` are composed.
	ConditionLanguageVersion *string `pulumi:"conditionLanguageVersion"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the routing policy rule list to.
	LoadBalancerId *string `pulumi:"loadBalancerId"`
	// The name for this list of routing rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `exampleRoutingRules`
	Name *string `pulumi:"name"`
	// (Updatable) The list of routing rules.
	Rules []LoadBalancerRoutingPolicyRule `pulumi:"rules"`
	State *string                         `pulumi:"state"`
}

type LoadBalancerRoutingPolicyState struct {
	// (Updatable) The version of the language in which `condition` of `rules` are composed.
	ConditionLanguageVersion pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the routing policy rule list to.
	LoadBalancerId pulumi.StringPtrInput
	// The name for this list of routing rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `exampleRoutingRules`
	Name pulumi.StringPtrInput
	// (Updatable) The list of routing rules.
	Rules LoadBalancerRoutingPolicyRuleArrayInput
	State pulumi.StringPtrInput
}

func (LoadBalancerRoutingPolicyState) ElementType() reflect.Type {
	return reflect.TypeOf((*loadBalancerRoutingPolicyState)(nil)).Elem()
}

type loadBalancerRoutingPolicyArgs struct {
	// (Updatable) The version of the language in which `condition` of `rules` are composed.
	ConditionLanguageVersion string `pulumi:"conditionLanguageVersion"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the routing policy rule list to.
	LoadBalancerId string `pulumi:"loadBalancerId"`
	// The name for this list of routing rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `exampleRoutingRules`
	Name *string `pulumi:"name"`
	// (Updatable) The list of routing rules.
	Rules []LoadBalancerRoutingPolicyRule `pulumi:"rules"`
}

// The set of arguments for constructing a LoadBalancerRoutingPolicy resource.
type LoadBalancerRoutingPolicyArgs struct {
	// (Updatable) The version of the language in which `condition` of `rules` are composed.
	ConditionLanguageVersion pulumi.StringInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the routing policy rule list to.
	LoadBalancerId pulumi.StringInput
	// The name for this list of routing rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `exampleRoutingRules`
	Name pulumi.StringPtrInput
	// (Updatable) The list of routing rules.
	Rules LoadBalancerRoutingPolicyRuleArrayInput
}

func (LoadBalancerRoutingPolicyArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*loadBalancerRoutingPolicyArgs)(nil)).Elem()
}

type LoadBalancerRoutingPolicyInput interface {
	pulumi.Input

	ToLoadBalancerRoutingPolicyOutput() LoadBalancerRoutingPolicyOutput
	ToLoadBalancerRoutingPolicyOutputWithContext(ctx context.Context) LoadBalancerRoutingPolicyOutput
}

func (*LoadBalancerRoutingPolicy) ElementType() reflect.Type {
	return reflect.TypeOf((**LoadBalancerRoutingPolicy)(nil)).Elem()
}

func (i *LoadBalancerRoutingPolicy) ToLoadBalancerRoutingPolicyOutput() LoadBalancerRoutingPolicyOutput {
	return i.ToLoadBalancerRoutingPolicyOutputWithContext(context.Background())
}

func (i *LoadBalancerRoutingPolicy) ToLoadBalancerRoutingPolicyOutputWithContext(ctx context.Context) LoadBalancerRoutingPolicyOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerRoutingPolicyOutput)
}

// LoadBalancerRoutingPolicyArrayInput is an input type that accepts LoadBalancerRoutingPolicyArray and LoadBalancerRoutingPolicyArrayOutput values.
// You can construct a concrete instance of `LoadBalancerRoutingPolicyArrayInput` via:
//
//	LoadBalancerRoutingPolicyArray{ LoadBalancerRoutingPolicyArgs{...} }
type LoadBalancerRoutingPolicyArrayInput interface {
	pulumi.Input

	ToLoadBalancerRoutingPolicyArrayOutput() LoadBalancerRoutingPolicyArrayOutput
	ToLoadBalancerRoutingPolicyArrayOutputWithContext(context.Context) LoadBalancerRoutingPolicyArrayOutput
}

type LoadBalancerRoutingPolicyArray []LoadBalancerRoutingPolicyInput

func (LoadBalancerRoutingPolicyArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*LoadBalancerRoutingPolicy)(nil)).Elem()
}

func (i LoadBalancerRoutingPolicyArray) ToLoadBalancerRoutingPolicyArrayOutput() LoadBalancerRoutingPolicyArrayOutput {
	return i.ToLoadBalancerRoutingPolicyArrayOutputWithContext(context.Background())
}

func (i LoadBalancerRoutingPolicyArray) ToLoadBalancerRoutingPolicyArrayOutputWithContext(ctx context.Context) LoadBalancerRoutingPolicyArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerRoutingPolicyArrayOutput)
}

// LoadBalancerRoutingPolicyMapInput is an input type that accepts LoadBalancerRoutingPolicyMap and LoadBalancerRoutingPolicyMapOutput values.
// You can construct a concrete instance of `LoadBalancerRoutingPolicyMapInput` via:
//
//	LoadBalancerRoutingPolicyMap{ "key": LoadBalancerRoutingPolicyArgs{...} }
type LoadBalancerRoutingPolicyMapInput interface {
	pulumi.Input

	ToLoadBalancerRoutingPolicyMapOutput() LoadBalancerRoutingPolicyMapOutput
	ToLoadBalancerRoutingPolicyMapOutputWithContext(context.Context) LoadBalancerRoutingPolicyMapOutput
}

type LoadBalancerRoutingPolicyMap map[string]LoadBalancerRoutingPolicyInput

func (LoadBalancerRoutingPolicyMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*LoadBalancerRoutingPolicy)(nil)).Elem()
}

func (i LoadBalancerRoutingPolicyMap) ToLoadBalancerRoutingPolicyMapOutput() LoadBalancerRoutingPolicyMapOutput {
	return i.ToLoadBalancerRoutingPolicyMapOutputWithContext(context.Background())
}

func (i LoadBalancerRoutingPolicyMap) ToLoadBalancerRoutingPolicyMapOutputWithContext(ctx context.Context) LoadBalancerRoutingPolicyMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(LoadBalancerRoutingPolicyMapOutput)
}

type LoadBalancerRoutingPolicyOutput struct{ *pulumi.OutputState }

func (LoadBalancerRoutingPolicyOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**LoadBalancerRoutingPolicy)(nil)).Elem()
}

func (o LoadBalancerRoutingPolicyOutput) ToLoadBalancerRoutingPolicyOutput() LoadBalancerRoutingPolicyOutput {
	return o
}

func (o LoadBalancerRoutingPolicyOutput) ToLoadBalancerRoutingPolicyOutputWithContext(ctx context.Context) LoadBalancerRoutingPolicyOutput {
	return o
}

// (Updatable) The version of the language in which `condition` of `rules` are composed.
func (o LoadBalancerRoutingPolicyOutput) ConditionLanguageVersion() pulumi.StringOutput {
	return o.ApplyT(func(v *LoadBalancerRoutingPolicy) pulumi.StringOutput { return v.ConditionLanguageVersion }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the load balancer to add the routing policy rule list to.
func (o LoadBalancerRoutingPolicyOutput) LoadBalancerId() pulumi.StringOutput {
	return o.ApplyT(func(v *LoadBalancerRoutingPolicy) pulumi.StringOutput { return v.LoadBalancerId }).(pulumi.StringOutput)
}

// The name for this list of routing rules. It must be unique and it cannot be changed. Avoid entering confidential information.  Example: `exampleRoutingRules`
func (o LoadBalancerRoutingPolicyOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *LoadBalancerRoutingPolicy) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

// (Updatable) The list of routing rules.
func (o LoadBalancerRoutingPolicyOutput) Rules() LoadBalancerRoutingPolicyRuleArrayOutput {
	return o.ApplyT(func(v *LoadBalancerRoutingPolicy) LoadBalancerRoutingPolicyRuleArrayOutput { return v.Rules }).(LoadBalancerRoutingPolicyRuleArrayOutput)
}

func (o LoadBalancerRoutingPolicyOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *LoadBalancerRoutingPolicy) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

type LoadBalancerRoutingPolicyArrayOutput struct{ *pulumi.OutputState }

func (LoadBalancerRoutingPolicyArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*LoadBalancerRoutingPolicy)(nil)).Elem()
}

func (o LoadBalancerRoutingPolicyArrayOutput) ToLoadBalancerRoutingPolicyArrayOutput() LoadBalancerRoutingPolicyArrayOutput {
	return o
}

func (o LoadBalancerRoutingPolicyArrayOutput) ToLoadBalancerRoutingPolicyArrayOutputWithContext(ctx context.Context) LoadBalancerRoutingPolicyArrayOutput {
	return o
}

func (o LoadBalancerRoutingPolicyArrayOutput) Index(i pulumi.IntInput) LoadBalancerRoutingPolicyOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *LoadBalancerRoutingPolicy {
		return vs[0].([]*LoadBalancerRoutingPolicy)[vs[1].(int)]
	}).(LoadBalancerRoutingPolicyOutput)
}

type LoadBalancerRoutingPolicyMapOutput struct{ *pulumi.OutputState }

func (LoadBalancerRoutingPolicyMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*LoadBalancerRoutingPolicy)(nil)).Elem()
}

func (o LoadBalancerRoutingPolicyMapOutput) ToLoadBalancerRoutingPolicyMapOutput() LoadBalancerRoutingPolicyMapOutput {
	return o
}

func (o LoadBalancerRoutingPolicyMapOutput) ToLoadBalancerRoutingPolicyMapOutputWithContext(ctx context.Context) LoadBalancerRoutingPolicyMapOutput {
	return o
}

func (o LoadBalancerRoutingPolicyMapOutput) MapIndex(k pulumi.StringInput) LoadBalancerRoutingPolicyOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *LoadBalancerRoutingPolicy {
		return vs[0].(map[string]*LoadBalancerRoutingPolicy)[vs[1].(string)]
	}).(LoadBalancerRoutingPolicyOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*LoadBalancerRoutingPolicyInput)(nil)).Elem(), &LoadBalancerRoutingPolicy{})
	pulumi.RegisterInputType(reflect.TypeOf((*LoadBalancerRoutingPolicyArrayInput)(nil)).Elem(), LoadBalancerRoutingPolicyArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*LoadBalancerRoutingPolicyMapInput)(nil)).Elem(), LoadBalancerRoutingPolicyMap{})
	pulumi.RegisterOutputType(LoadBalancerRoutingPolicyOutput{})
	pulumi.RegisterOutputType(LoadBalancerRoutingPolicyArrayOutput{})
	pulumi.RegisterOutputType(LoadBalancerRoutingPolicyMapOutput{})
}
