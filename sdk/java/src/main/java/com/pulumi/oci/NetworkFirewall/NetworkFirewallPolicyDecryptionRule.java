// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.NetworkFirewall.NetworkFirewallPolicyDecryptionRuleArgs;
import com.pulumi.oci.NetworkFirewall.inputs.NetworkFirewallPolicyDecryptionRuleState;
import com.pulumi.oci.NetworkFirewall.outputs.NetworkFirewallPolicyDecryptionRuleCondition;
import com.pulumi.oci.NetworkFirewall.outputs.NetworkFirewallPolicyDecryptionRulePosition;
import com.pulumi.oci.Utilities;
import java.lang.String;
import java.util.Optional;
import javax.annotation.Nullable;

/**
 * This resource provides the Network Firewall Policy Decryption Rule resource in Oracle Cloud Infrastructure Network Firewall service.
 * 
 * Creates a new Decryption Rule for the Network Firewall Policy.
 * 
 * ## Example Usage
 * 
 * ```java
 * package generated_program;
 * 
 * import com.pulumi.Context;
 * import com.pulumi.Pulumi;
 * import com.pulumi.core.Output;
 * import com.pulumi.oci.NetworkFirewall.NetworkFirewallPolicyDecryptionRule;
 * import com.pulumi.oci.NetworkFirewall.NetworkFirewallPolicyDecryptionRuleArgs;
 * import com.pulumi.oci.NetworkFirewall.inputs.NetworkFirewallPolicyDecryptionRuleConditionArgs;
 * import com.pulumi.oci.NetworkFirewall.inputs.NetworkFirewallPolicyDecryptionRulePositionArgs;
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
 *         var testNetworkFirewallPolicyDecryptionRule = new NetworkFirewallPolicyDecryptionRule(&#34;testNetworkFirewallPolicyDecryptionRule&#34;, NetworkFirewallPolicyDecryptionRuleArgs.builder()        
 *             .lifecycle(%!v(PANIC=Format method: runtime error: invalid memory address or nil pointer dereference))
 *             .action(var_.network_firewall_policy_decryption_rule_action())
 *             .condition(NetworkFirewallPolicyDecryptionRuleConditionArgs.builder()
 *                 .destinationAddresses(var_.network_firewall_policy_decryption_rule_condition_destination_address())
 *                 .sourceAddresses(var_.network_firewall_policy_decryption_rule_condition_source_address())
 *                 .build())
 *             .position(NetworkFirewallPolicyDecryptionRulePositionArgs.builder()
 *                 .afterRule(var_.network_firewall_policy_decryption_rule_position_after_rule())
 *                 .beforeRule(var_.network_firewall_policy_decryption_rule_position_before_rule())
 *                 .build())
 *             .networkFirewallPolicyId(oci_network_firewall_network_firewall_policy.test_network_firewall_policy().id())
 *             .decryptionProfile(var_.network_firewall_policy_decryption_rule_decryption_profile())
 *             .secret(var_.network_firewall_policy_decryption_rule_secret())
 *             .build());
 * 
 *     }
 * }
 * ```
 * 
 * ## Import
 * 
 * NetworkFirewallPolicyDecryptionRules can be imported using the `name`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:NetworkFirewall/networkFirewallPolicyDecryptionRule:NetworkFirewallPolicyDecryptionRule test_network_firewall_policy_decryption_rule &#34;networkFirewallPolicies/{networkFirewallPolicyId}/decryptionRules/{decryptionRuleName}&#34;
 * ```
 * 
 */
@ResourceType(type="oci:NetworkFirewall/networkFirewallPolicyDecryptionRule:NetworkFirewallPolicyDecryptionRule")
public class NetworkFirewallPolicyDecryptionRule extends com.pulumi.resources.CustomResource {
    /**
     * (Updatable) Action:
     * * NO_DECRYPT - Matching traffic is not decrypted.
     * * DECRYPT - Matching traffic is decrypted with the specified `secret` according to the specified `decryptionProfile`.
     * 
     */
    @Export(name="action", refs={String.class}, tree="[0]")
    private Output<String> action;

    /**
     * @return (Updatable) Action:
     * * NO_DECRYPT - Matching traffic is not decrypted.
     * * DECRYPT - Matching traffic is decrypted with the specified `secret` according to the specified `decryptionProfile`.
     * 
     */
    public Output<String> action() {
        return this.action;
    }
    /**
     * (Updatable) Match criteria used in Decryption Rule used on the firewall policy rules. The resources mentioned must already be present in the policy before being referenced in the rule.
     * 
     */
    @Export(name="condition", refs={NetworkFirewallPolicyDecryptionRuleCondition.class}, tree="[0]")
    private Output<NetworkFirewallPolicyDecryptionRuleCondition> condition;

    /**
     * @return (Updatable) Match criteria used in Decryption Rule used on the firewall policy rules. The resources mentioned must already be present in the policy before being referenced in the rule.
     * 
     */
    public Output<NetworkFirewallPolicyDecryptionRuleCondition> condition() {
        return this.condition;
    }
    /**
     * (Updatable) The name of the decryption profile to use.
     * 
     */
    @Export(name="decryptionProfile", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> decryptionProfile;

    /**
     * @return (Updatable) The name of the decryption profile to use.
     * 
     */
    public Output<Optional<String>> decryptionProfile() {
        return Codegen.optional(this.decryptionProfile);
    }
    /**
     * Name for the decryption rule, must be unique within the policy.
     * 
     */
    @Export(name="name", refs={String.class}, tree="[0]")
    private Output<String> name;

    /**
     * @return Name for the decryption rule, must be unique within the policy.
     * 
     */
    public Output<String> name() {
        return this.name;
    }
    /**
     * Unique Network Firewall Policy identifier
     * 
     */
    @Export(name="networkFirewallPolicyId", refs={String.class}, tree="[0]")
    private Output<String> networkFirewallPolicyId;

    /**
     * @return Unique Network Firewall Policy identifier
     * 
     */
    public Output<String> networkFirewallPolicyId() {
        return this.networkFirewallPolicyId;
    }
    /**
     * OCID of the Network Firewall Policy this decryption rule belongs to.
     * 
     */
    @Export(name="parentResourceId", refs={String.class}, tree="[0]")
    private Output<String> parentResourceId;

    /**
     * @return OCID of the Network Firewall Policy this decryption rule belongs to.
     * 
     */
    public Output<String> parentResourceId() {
        return this.parentResourceId;
    }
    /**
     * (Updatable) An object which defines the position of the rule. Only one of `after_rule` or `before_rule` should be provided.
     * 
     */
    @Export(name="position", refs={NetworkFirewallPolicyDecryptionRulePosition.class}, tree="[0]")
    private Output<NetworkFirewallPolicyDecryptionRulePosition> position;

    /**
     * @return (Updatable) An object which defines the position of the rule. Only one of `after_rule` or `before_rule` should be provided.
     * 
     */
    public Output<NetworkFirewallPolicyDecryptionRulePosition> position() {
        return this.position;
    }
    @Export(name="priorityOrder", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> priorityOrder;

    public Output<Optional<String>> priorityOrder() {
        return Codegen.optional(this.priorityOrder);
    }
    /**
     * (Updatable) The name of a mapped secret. Its `type` must match that of the specified decryption profile.
     * 
     */
    @Export(name="secret", refs={String.class}, tree="[0]")
    private Output</* @Nullable */ String> secret;

    /**
     * @return (Updatable) The name of a mapped secret. Its `type` must match that of the specified decryption profile.
     * 
     */
    public Output<Optional<String>> secret() {
        return Codegen.optional(this.secret);
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public NetworkFirewallPolicyDecryptionRule(String name) {
        this(name, NetworkFirewallPolicyDecryptionRuleArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public NetworkFirewallPolicyDecryptionRule(String name, NetworkFirewallPolicyDecryptionRuleArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public NetworkFirewallPolicyDecryptionRule(String name, NetworkFirewallPolicyDecryptionRuleArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:NetworkFirewall/networkFirewallPolicyDecryptionRule:NetworkFirewallPolicyDecryptionRule", name, args == null ? NetworkFirewallPolicyDecryptionRuleArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private NetworkFirewallPolicyDecryptionRule(String name, Output<String> id, @Nullable NetworkFirewallPolicyDecryptionRuleState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:NetworkFirewall/networkFirewallPolicyDecryptionRule:NetworkFirewallPolicyDecryptionRule", name, state, makeResourceOptions(options, id));
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
    public static NetworkFirewallPolicyDecryptionRule get(String name, Output<String> id, @Nullable NetworkFirewallPolicyDecryptionRuleState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new NetworkFirewallPolicyDecryptionRule(name, id, state, options);
    }
}