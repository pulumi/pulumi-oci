// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Budget;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Budget.BudgetArgs;
import com.pulumi.oci.Budget.inputs.BudgetState;
import com.pulumi.oci.Utilities;
import java.lang.Double;
import java.lang.Integer;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Budget resource in Oracle Cloud Infrastructure Budget service.
 * 
 * Creates a new Budget.
 * 
 * ## Example Usage
 * 
 * ## Import
 * 
 * Budgets can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Budget/budget:Budget test_budget &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Budget/budget:Budget")
public class Budget extends com.pulumi.resources.CustomResource {
    /**
     * The actual spend in currency for the current budget cycle
     * 
     */
    @Export(name="actualSpend", type=Double.class, parameters={})
    private Output<Double> actualSpend;

    /**
     * @return The actual spend in currency for the current budget cycle
     * 
     */
    public Output<Double> actualSpend() {
        return this.actualSpend;
    }
    /**
     * Total number of alert rules in the budget
     * 
     */
    @Export(name="alertRuleCount", type=Integer.class, parameters={})
    private Output<Integer> alertRuleCount;

    /**
     * @return Total number of alert rules in the budget
     * 
     */
    public Output<Integer> alertRuleCount() {
        return this.alertRuleCount;
    }
    /**
     * (Updatable) The amount of the budget expressed as a whole number in the currency of the customer&#39;s rate card.
     * 
     */
    @Export(name="amount", type=Integer.class, parameters={})
    private Output<Integer> amount;

    /**
     * @return (Updatable) The amount of the budget expressed as a whole number in the currency of the customer&#39;s rate card.
     * 
     */
    public Output<Integer> amount() {
        return this.amount;
    }
    /**
     * (Updatable) The number of days offset from the first day of the month, at which the budget processing period starts. In months that have fewer days than this value, processing will begin on the last day of that month. For example, for a value of 12, processing starts every month on the 12th at midnight.
     * 
     */
    @Export(name="budgetProcessingPeriodStartOffset", type=Integer.class, parameters={})
    private Output<Integer> budgetProcessingPeriodStartOffset;

    /**
     * @return (Updatable) The number of days offset from the first day of the month, at which the budget processing period starts. In months that have fewer days than this value, processing will begin on the last day of that month. For example, for a value of 12, processing starts every month on the 12th at midnight.
     * 
     */
    public Output<Integer> budgetProcessingPeriodStartOffset() {
        return this.budgetProcessingPeriodStartOffset;
    }
    /**
     * The OCID of the tenancy
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return The OCID of the tenancy
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) The description of the budget.
     * 
     */
    @Export(name="description", type=String.class, parameters={})
    private Output<String> description;

    /**
     * @return (Updatable) The description of the budget.
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) The displayName of the budget.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) The displayName of the budget.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * The forecasted spend in currency by the end of the current budget cycle
     * 
     */
    @Export(name="forecastedSpend", type=Double.class, parameters={})
    private Output<Double> forecastedSpend;

    /**
     * @return The forecasted spend in currency by the end of the current budget cycle
     * 
     */
    public Output<Double> forecastedSpend() {
        return this.forecastedSpend;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * (Updatable) The reset period for the budget. Valid value is MONTHLY.
     * 
     */
    @Export(name="resetPeriod", type=String.class, parameters={})
    private Output<String> resetPeriod;

    /**
     * @return (Updatable) The reset period for the budget. Valid value is MONTHLY.
     * 
     */
    public Output<String> resetPeriod() {
        return this.resetPeriod;
    }
    /**
     * The current state of the budget.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the budget.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * This is DEPRECTAED. Set the target compartment id in targets instead.
     * 
     * @deprecated
     * The &#39;target_compartment_id&#39; field has been deprecated. Please use &#39;target_type&#39; instead.
     * 
     */
    @Deprecated /* The 'target_compartment_id' field has been deprecated. Please use 'target_type' instead. */
    @Export(name="targetCompartmentId", type=String.class, parameters={})
    private Output<String> targetCompartmentId;

    /**
     * @return This is DEPRECTAED. Set the target compartment id in targets instead.
     * 
     */
    public Output<String> targetCompartmentId() {
        return this.targetCompartmentId;
    }
    /**
     * The type of target on which the budget is applied.
     * 
     */
    @Export(name="targetType", type=String.class, parameters={})
    private Output<String> targetType;

    /**
     * @return The type of target on which the budget is applied.
     * 
     */
    public Output<String> targetType() {
        return this.targetType;
    }
    /**
     * The list of targets on which the budget is applied. If targetType is &#34;COMPARTMENT&#34;, targets contains list of compartment OCIDs. If targetType is &#34;TAG&#34;, targets contains list of cost tracking tag identifiers in the form of &#34;{tagNamespace}.{tagKey}.{tagValue}&#34;. Curerntly, the array should contain EXACT ONE item.
     * 
     */
    @Export(name="targets", type=List.class, parameters={String.class})
    private Output<List<String>> targets;

    /**
     * @return The list of targets on which the budget is applied. If targetType is &#34;COMPARTMENT&#34;, targets contains list of compartment OCIDs. If targetType is &#34;TAG&#34;, targets contains list of cost tracking tag identifiers in the form of &#34;{tagNamespace}.{tagKey}.{tagValue}&#34;. Curerntly, the array should contain EXACT ONE item.
     * 
     */
    public Output<List<String>> targets() {
        return this.targets;
    }
    /**
     * Time that budget was created
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return Time that budget was created
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time that the budget spend was last computed
     * 
     */
    @Export(name="timeSpendComputed", type=String.class, parameters={})
    private Output<String> timeSpendComputed;

    /**
     * @return The time that the budget spend was last computed
     * 
     */
    public Output<String> timeSpendComputed() {
        return this.timeSpendComputed;
    }
    /**
     * Time that budget was updated
     * 
     */
    @Export(name="timeUpdated", type=String.class, parameters={})
    private Output<String> timeUpdated;

    /**
     * @return Time that budget was updated
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * Version of the budget. Starts from 1 and increments by 1.
     * 
     */
    @Export(name="version", type=Integer.class, parameters={})
    private Output<Integer> version;

    /**
     * @return Version of the budget. Starts from 1 and increments by 1.
     * 
     */
    public Output<Integer> version() {
        return this.version;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Budget(String name) {
        this(name, BudgetArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Budget(String name, BudgetArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Budget(String name, BudgetArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Budget/budget:Budget", name, args == null ? BudgetArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private Budget(String name, Output<String> id, @Nullable BudgetState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Budget/budget:Budget", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static Budget get(String name, Output<String> id, @Nullable BudgetState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Budget(name, id, state, options);
    }
}
