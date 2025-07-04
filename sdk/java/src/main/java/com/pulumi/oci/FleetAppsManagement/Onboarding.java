// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.FleetAppsManagement.OnboardingArgs;
import com.pulumi.oci.FleetAppsManagement.inputs.OnboardingState;
import com.pulumi.oci.FleetAppsManagement.outputs.OnboardingAppliedPolicy;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Onboarding resource in Oracle Cloud Infrastructure Fleet Apps Management service.
 * 
 * Onboard a tenant to Fleet Application Management.
 * The onboarding process lets Fleet Application Management create a few required policies that you need to start using it
 * and its features.
 * 
 * ## Example Usage
 * 
 * &lt;!--Start PulumiCodeChooser --&gt;
 * <pre>
 * {@code
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.FleetAppsManagement.Onboarding;
 * import com.pulumi.oci.FleetAppsManagement.OnboardingArgs;
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
 *         var testOnboarding = new Onboarding("testOnboarding", OnboardingArgs.builder()
 *             .compartmentId(compartmentId)
 *             .isCostTrackingTagEnabled(onboardingIsCostTrackingTagEnabled)
 *             .isFamsTagEnabled(onboardingIsFamsTagEnabled)
 *             .build());
 * 
 *     }
 * }
 * }
 * </pre>
 * &lt;!--End PulumiCodeChooser --&gt;
 * 
 * ## Import
 * 
 * Onboardings can be imported using the `id`, e.g.
 * 
 * ```sh
 * $ pulumi import oci:FleetAppsManagement/onboarding:Onboarding test_onboarding &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:FleetAppsManagement/onboarding:Onboarding")
public class Onboarding extends com.pulumi.resources.CustomResource {
    /**
     * Summary of the Fleet Application Management Onboard Policy.
     * 
     */
    @Export(name="appliedPolicies", refs={List.class,OnboardingAppliedPolicy.class}, tree="[0,1]")
    private Output<List<OnboardingAppliedPolicy>> appliedPolicies;

    /**
     * @return Summary of the Fleet Application Management Onboard Policy.
     * 
     */
    public Output<List<OnboardingAppliedPolicy>> appliedPolicies() {
        return this.appliedPolicies;
    }
    /**
     * Tenancy OCID
     * 
     */
    @Export(name="compartmentId", refs={String.class}, tree="[0]")
    private Output<String> compartmentId;

    /**
     * @return Tenancy OCID
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * Defined tags for this resource. Each key is predefined and scoped to a namespace. Example:
     * `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="definedTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> definedTags;

    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. Example:
     * `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> definedTags() {
        return this.definedTags;
    }
    /**
     * Provide discovery frequency.
     * 
     */
    @Export(name="discoveryFrequency", refs={String.class}, tree="[0]")
    private Output<String> discoveryFrequency;

    /**
     * @return Provide discovery frequency.
     * 
     */
    public Output<String> discoveryFrequency() {
        return this.discoveryFrequency;
    }
    /**
     * Simple key-value pair that is applied without any predefined name, type or scope. Exists for
     * cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Export(name="freeformTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> freeformTags;

    /**
     * @return Simple key-value pair that is applied without any predefined name, type or scope. Exists for
     * cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Output<Map<String,String>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * A value determining if the cost tracking tag is enabled or not. Allow
     * Fleet Application Management to tag resources with cost tracking tag using &#34;Oracle$FAMS-Tags.FAMSManaged&#34; tag.
     * 
     */
    @Export(name="isCostTrackingTagEnabled", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isCostTrackingTagEnabled;

    /**
     * @return A value determining if the cost tracking tag is enabled or not. Allow
     * Fleet Application Management to tag resources with cost tracking tag using &#34;Oracle$FAMS-Tags.FAMSManaged&#34; tag.
     * 
     */
    public Output<Boolean> isCostTrackingTagEnabled() {
        return this.isCostTrackingTagEnabled;
    }
    /**
     * A value determining if the Fleet Application Management tagging is enabled or not.
     * Allow Fleet Application Management to tag resources with fleet name using &#34;Oracle$FAMS-Tags.FleetName&#34; tag.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the
     * new property values
     * 
     */
    @Export(name="isFamsTagEnabled", refs={Boolean.class}, tree="[0]")
    private Output<Boolean> isFamsTagEnabled;

    /**
     * @return A value determining if the Fleet Application Management tagging is enabled or not.
     * Allow Fleet Application Management to tag resources with fleet name using &#34;Oracle$FAMS-Tags.FleetName&#34; tag.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the
     * new property values
     * 
     */
    public Output<Boolean> isFamsTagEnabled() {
        return this.isFamsTagEnabled;
    }
    /**
     * Associated region
     * 
     */
    @Export(name="resourceRegion", refs={String.class}, tree="[0]")
    private Output<String> resourceRegion;

    /**
     * @return Associated region
     * 
     */
    public Output<String> resourceRegion() {
        return this.resourceRegion;
    }
    /**
     * The current state of the Onboarding.
     * 
     */
    @Export(name="state", refs={String.class}, tree="[0]")
    private Output<String> state;

    /**
     * @return The current state of the Onboarding.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * System tags for this resource. Each key is predefined and scoped to a namespace. Example:
     * `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    @Export(name="systemTags", refs={Map.class,String.class}, tree="[0,1,1]")
    private Output<Map<String,String>> systemTags;

    /**
     * @return System tags for this resource. Each key is predefined and scoped to a namespace. Example:
     * `{&#34;orcl-cloud.free-tier-retained&#34;: &#34;true&#34;}`
     * 
     */
    public Output<Map<String,String>> systemTags() {
        return this.systemTags;
    }
    /**
     * The time this resource was created. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeCreated", refs={String.class}, tree="[0]")
    private Output<String> timeCreated;

    /**
     * @return The time this resource was created. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The time this resource was last updated. An RFC3339 formatted datetime string.
     * 
     */
    @Export(name="timeUpdated", refs={String.class}, tree="[0]")
    private Output<String> timeUpdated;

    /**
     * @return The time this resource was last updated. An RFC3339 formatted datetime string.
     * 
     */
    public Output<String> timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * The version of Fleet Application Management that the tenant is onboarded to.
     * 
     */
    @Export(name="version", refs={String.class}, tree="[0]")
    private Output<String> version;

    /**
     * @return The version of Fleet Application Management that the tenant is onboarded to.
     * 
     */
    public Output<String> version() {
        return this.version;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Onboarding(java.lang.String name) {
        this(name, OnboardingArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Onboarding(java.lang.String name, OnboardingArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Onboarding(java.lang.String name, OnboardingArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:FleetAppsManagement/onboarding:Onboarding", name, makeArgs(args, options), makeResourceOptions(options, Codegen.empty()), false);
    }

    private Onboarding(java.lang.String name, Output<java.lang.String> id, @Nullable OnboardingState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:FleetAppsManagement/onboarding:Onboarding", name, state, makeResourceOptions(options, id), false);
    }

    private static OnboardingArgs makeArgs(OnboardingArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        if (options != null && options.getUrn().isPresent()) {
            return null;
        }
        return args == null ? OnboardingArgs.Empty : args;
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<java.lang.String> id) {
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
    public static Onboarding get(java.lang.String name, Output<java.lang.String> id, @Nullable OnboardingState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Onboarding(name, id, state, options);
    }
}
