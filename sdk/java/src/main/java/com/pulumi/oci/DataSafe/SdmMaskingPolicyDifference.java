// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DataSafe.SdmMaskingPolicyDifferenceArgs;
import com.pulumi.oci.DataSafe.inputs.SdmMaskingPolicyDifferenceState;
import com.pulumi.oci.Utilities;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Sdm Masking Policy Difference resource in Oracle Cloud Infrastructure Data Safe service.
 * 
 * Creates SDM masking policy difference for the specified masking policy. It finds the difference between
 * masking columns of the masking policy and sensitive columns of the SDM. After performing this operation,
 * you can use ListDifferenceColumns to view the difference columns, PatchSdmMaskingPolicyDifferenceColumns
 * to specify the action you want perform on these columns, and then ApplySdmMaskingPolicyDifference to process the
 * difference columns and apply them to the masking policy.
 * 
 * ## Example Usage
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.DataSafe.SdmMaskingPolicyDifference;
 * import com.pulumi.oci.DataSafe.SdmMaskingPolicyDifferenceArgs;
 * import java.util.List;
 * import java.util.ArrayList;
 * import java.util.Map;
 * import java.io.File;
 * import java.nio.file.Files;
 * import java.nio.file.Paths;
 * 
 * public class App {
 *     public static void main(String[] args) {
 *         Pulumi.run(App::stack);
 *     }
 * 
 *     public static void stack(Context ctx) {
 *         var testSdmMaskingPolicyDifference = new SdmMaskingPolicyDifference(&#34;testSdmMaskingPolicyDifference&#34;, SdmMaskingPolicyDifferenceArgs.builder()        
 *             .compartmentId(var_.compartment_id())
 *             .maskingPolicyId(oci_data_safe_masking_policy.test_masking_policy().id())
 *             .definedTags(Map.of(&#34;Operations.CostCenter&#34;, &#34;42&#34;))
 *             .differenceType(var_.sdm_masking_policy_difference_difference_type())
 *             .displayName(var_.sdm_masking_policy_difference_display_name())
 *             .freeformTags(Map.of(&#34;Department&#34;, &#34;Finance&#34;))
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * SdmMaskingPolicyDifferences can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:DataSafe/sdmMaskingPolicyDifference:SdmMaskingPolicyDifference test_sdm_masking_policy_difference &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:DataSafe/sdmMaskingPolicyDifference:SdmMaskingPolicyDifference")
public class SdmMaskingPolicyDifference extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) The OCID of the compartment where the SDM masking policy difference resource should be created.
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the compartment where the SDM masking policy difference resource should be created.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * The type of the SDM masking policy difference. It defines the difference scope. NEW identifies new sensitive columns in the sensitive data model that are not in the masking policy. DELETED identifies columns that are present in the masking policy but have been deleted from the sensitive data model. MODIFIED identifies columns that are present in the sensitive data model as well as the masking policy but some of their attributes have been modified. ALL covers all the above three scenarios and reports new, deleted and modified columns.
     * 
     */
    @Export(name="differenceType", type=String.class, parameters={})
    private Output<String> differenceType;

    /**
     * @return The type of the SDM masking policy difference. It defines the difference scope. NEW identifies new sensitive columns in the sensitive data model that are not in the masking policy. DELETED identifies columns that are present in the masking policy but have been deleted from the sensitive data model. MODIFIED identifies columns that are present in the sensitive data model as well as the masking policy but some of their attributes have been modified. ALL covers all the above three scenarios and reports new, deleted and modified columns.
     * 
     */
    public Output<String> differenceType() {
        return this.differenceType;
    }
    /**
     * (Updatable) A user-friendly name for the SDM masking policy difference. Does not have to be unique, and it is changeable. Avoid entering confidential information.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly name for the SDM masking policy difference. Does not have to be unique, and it is changeable. Avoid entering confidential information.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm)  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * The OCID of the masking policy. Note that if the masking policy is not associated with an SDM, CreateSdmMaskingPolicyDifference operation won&#39;t be allowed.
     * 
     */
    @Export(name="maskingPolicyId", type=String.class, parameters={})
    private Output<String> maskingPolicyId;

    /**
     * @return The OCID of the masking policy. Note that if the masking policy is not associated with an SDM, CreateSdmMaskingPolicyDifference operation won&#39;t be allowed.
     * 
     */
    public Output<String> maskingPolicyId() {
        return this.maskingPolicyId;
    }
    /**
     * The OCID of the sensitive data model associated with the SDM masking policy difference.
     * 
     */
    @Export(name="sensitiveDataModelId", type=String.class, parameters={})
    private Output<String> sensitiveDataModelId;

    /**
     * @return The OCID of the sensitive data model associated with the SDM masking policy difference.
     * 
     */
    public Output<String> sensitiveDataModelId() {
        return this.sensitiveDataModelId;
    }
    /**
     * The current state of the SDM masking policy difference.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state of the SDM masking policy difference.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see Resource Tags. Example: `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,Object>> systemTags() {
        return this.systemTags;
    }
    /**
     * The date and time the SDM masking policy difference was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return The date and time the SDM masking policy difference was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The date and time the SDM masking policy difference creation started, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    @Export(name="timeCreationStarted", type=String.class, parameters={})
    private Output<String> timeCreationStarted;

    /**
     * @return The date and time the SDM masking policy difference creation started, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
     * 
     */
    public Output<String> timeCreationStarted() {
        return this.timeCreationStarted;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public SdmMaskingPolicyDifference(String name) {
        this(name, SdmMaskingPolicyDifferenceArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public SdmMaskingPolicyDifference(String name, SdmMaskingPolicyDifferenceArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public SdmMaskingPolicyDifference(String name, SdmMaskingPolicyDifferenceArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataSafe/sdmMaskingPolicyDifference:SdmMaskingPolicyDifference", name, args == null ? SdmMaskingPolicyDifferenceArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private SdmMaskingPolicyDifference(String name, Output<String> id, @Nullable SdmMaskingPolicyDifferenceState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataSafe/sdmMaskingPolicyDifference:SdmMaskingPolicyDifference", name, state, makeResourceOptions(options, id));
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
    public static SdmMaskingPolicyDifference get(String name, Output<String> id, @Nullable SdmMaskingPolicyDifferenceState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new SdmMaskingPolicyDifference(name, id, state, options);
    }
}