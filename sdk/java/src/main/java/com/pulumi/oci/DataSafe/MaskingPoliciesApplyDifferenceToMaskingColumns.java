// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataSafe;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.DataSafe.MaskingPoliciesApplyDifferenceToMaskingColumnsArgs;
import com.pulumi.oci.DataSafe.inputs.MaskingPoliciesApplyDifferenceToMaskingColumnsState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import javax.annotation.Nullable;

@ResourceType(type="oci:DataSafe/maskingPoliciesApplyDifferenceToMaskingColumns:MaskingPoliciesApplyDifferenceToMaskingColumns")
public class MaskingPoliciesApplyDifferenceToMaskingColumns extends com.pulumi.resources.CustomResource {
    @Export(name="maskingPolicyId", type=String.class, parameters={})
    private Output<String> maskingPolicyId;

    public Output<String> maskingPolicyId() {
        return this.maskingPolicyId;
    }
    @Export(name="sdmMaskingPolicyDifferenceId", type=String.class, parameters={})
    private Output<String> sdmMaskingPolicyDifferenceId;

    public Output<String> sdmMaskingPolicyDifferenceId() {
        return this.sdmMaskingPolicyDifferenceId;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public MaskingPoliciesApplyDifferenceToMaskingColumns(String name) {
        this(name, MaskingPoliciesApplyDifferenceToMaskingColumnsArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public MaskingPoliciesApplyDifferenceToMaskingColumns(String name, MaskingPoliciesApplyDifferenceToMaskingColumnsArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public MaskingPoliciesApplyDifferenceToMaskingColumns(String name, MaskingPoliciesApplyDifferenceToMaskingColumnsArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataSafe/maskingPoliciesApplyDifferenceToMaskingColumns:MaskingPoliciesApplyDifferenceToMaskingColumns", name, args == null ? MaskingPoliciesApplyDifferenceToMaskingColumnsArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private MaskingPoliciesApplyDifferenceToMaskingColumns(String name, Output<String> id, @Nullable MaskingPoliciesApplyDifferenceToMaskingColumnsState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:DataSafe/maskingPoliciesApplyDifferenceToMaskingColumns:MaskingPoliciesApplyDifferenceToMaskingColumns", name, state, makeResourceOptions(options, id));
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
    public static MaskingPoliciesApplyDifferenceToMaskingColumns get(String name, Output<String> id, @Nullable MaskingPoliciesApplyDifferenceToMaskingColumnsState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new MaskingPoliciesApplyDifferenceToMaskingColumns(name, id, state, options);
    }
}