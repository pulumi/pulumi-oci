// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.oci.NetworkFirewall.inputs.NetworkFirewallPolicyApplicationListArgs;
import com.pulumi.oci.NetworkFirewall.inputs.NetworkFirewallPolicyDecryptionProfileArgs;
import com.pulumi.oci.NetworkFirewall.inputs.NetworkFirewallPolicyDecryptionRuleArgs;
import com.pulumi.oci.NetworkFirewall.inputs.NetworkFirewallPolicyIpAddressListArgs;
import com.pulumi.oci.NetworkFirewall.inputs.NetworkFirewallPolicyMappedSecretArgs;
import com.pulumi.oci.NetworkFirewall.inputs.NetworkFirewallPolicySecurityRuleArgs;
import com.pulumi.oci.NetworkFirewall.inputs.NetworkFirewallPolicyUrlListArgs;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NetworkFirewallPolicyArgs extends com.pulumi.resources.ResourceArgs {

    public static final NetworkFirewallPolicyArgs Empty = new NetworkFirewallPolicyArgs();

    /**
     * (Updatable) Map defining application lists of the policy. The value of an entry is a list of &#34;applications&#34;, each consisting of a protocol identifier (such as TCP, UDP, or ICMP) and protocol-specific parameters (such as a port range). The associated key is the identifier by which the application list is referenced.
     * 
     */
    @Import(name="applicationLists")
    private @Nullable Output<List<NetworkFirewallPolicyApplicationListArgs>> applicationLists;

    /**
     * @return (Updatable) Map defining application lists of the policy. The value of an entry is a list of &#34;applications&#34;, each consisting of a protocol identifier (such as TCP, UDP, or ICMP) and protocol-specific parameters (such as a port range). The associated key is the identifier by which the application list is referenced.
     * 
     */
    public Optional<Output<List<NetworkFirewallPolicyApplicationListArgs>>> applicationLists() {
        return Optional.ofNullable(this.applicationLists);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the NetworkFirewall Policy.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the NetworkFirewall Policy.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * (Updatable) Map defining decryption profiles of the policy. The value of an entry is a decryption profile. The associated key is the identifier by which the decryption profile is referenced.
     * 
     */
    @Import(name="decryptionProfiles")
    private @Nullable Output<List<NetworkFirewallPolicyDecryptionProfileArgs>> decryptionProfiles;

    /**
     * @return (Updatable) Map defining decryption profiles of the policy. The value of an entry is a decryption profile. The associated key is the identifier by which the decryption profile is referenced.
     * 
     */
    public Optional<Output<List<NetworkFirewallPolicyDecryptionProfileArgs>>> decryptionProfiles() {
        return Optional.ofNullable(this.decryptionProfiles);
    }

    /**
     * (Updatable) List of Decryption Rules defining the behavior of the policy. The first rule with a matching condition determines the action taken upon network traffic.
     * 
     */
    @Import(name="decryptionRules")
    private @Nullable Output<List<NetworkFirewallPolicyDecryptionRuleArgs>> decryptionRules;

    /**
     * @return (Updatable) List of Decryption Rules defining the behavior of the policy. The first rule with a matching condition determines the action taken upon network traffic.
     * 
     */
    public Optional<Output<List<NetworkFirewallPolicyDecryptionRuleArgs>>> decryptionRules() {
        return Optional.ofNullable(this.decryptionRules);
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A user-friendly optional name for the firewall policy. Avoid entering confidential information.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A user-friendly optional name for the firewall policy. Avoid entering confidential information.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * (Updatable) Map defining IP address lists of the policy. The value of an entry is a list of IP addresses or prefixes in CIDR notation. The associated key is the identifier by which the IP address list is referenced.
     * 
     */
    @Import(name="ipAddressLists")
    private @Nullable Output<List<NetworkFirewallPolicyIpAddressListArgs>> ipAddressLists;

    /**
     * @return (Updatable) Map defining IP address lists of the policy. The value of an entry is a list of IP addresses or prefixes in CIDR notation. The associated key is the identifier by which the IP address list is referenced.
     * 
     */
    public Optional<Output<List<NetworkFirewallPolicyIpAddressListArgs>>> ipAddressLists() {
        return Optional.ofNullable(this.ipAddressLists);
    }

    /**
     * (Updatable) Map defining secrets of the policy. The value of an entry is a &#34;mapped secret&#34; consisting of a purpose and source. The associated key is the identifier by which the mapped secret is referenced.
     * 
     */
    @Import(name="mappedSecrets")
    private @Nullable Output<List<NetworkFirewallPolicyMappedSecretArgs>> mappedSecrets;

    /**
     * @return (Updatable) Map defining secrets of the policy. The value of an entry is a &#34;mapped secret&#34; consisting of a purpose and source. The associated key is the identifier by which the mapped secret is referenced.
     * 
     */
    public Optional<Output<List<NetworkFirewallPolicyMappedSecretArgs>>> mappedSecrets() {
        return Optional.ofNullable(this.mappedSecrets);
    }

    /**
     * (Updatable) List of Security Rules defining the behavior of the policy. The first rule with a matching condition determines the action taken upon network traffic.
     * 
     */
    @Import(name="securityRules")
    private @Nullable Output<List<NetworkFirewallPolicySecurityRuleArgs>> securityRules;

    /**
     * @return (Updatable) List of Security Rules defining the behavior of the policy. The first rule with a matching condition determines the action taken upon network traffic.
     * 
     */
    public Optional<Output<List<NetworkFirewallPolicySecurityRuleArgs>>> securityRules() {
        return Optional.ofNullable(this.securityRules);
    }

    /**
     * (Updatable) Map defining URL pattern lists of the policy. The value of an entry is a list of URL patterns. The associated key is the identifier by which the URL pattern list is referenced.
     * 
     */
    @Import(name="urlLists")
    private @Nullable Output<List<NetworkFirewallPolicyUrlListArgs>> urlLists;

    /**
     * @return (Updatable) Map defining URL pattern lists of the policy. The value of an entry is a list of URL patterns. The associated key is the identifier by which the URL pattern list is referenced.
     * 
     */
    public Optional<Output<List<NetworkFirewallPolicyUrlListArgs>>> urlLists() {
        return Optional.ofNullable(this.urlLists);
    }

    private NetworkFirewallPolicyArgs() {}

    private NetworkFirewallPolicyArgs(NetworkFirewallPolicyArgs $) {
        this.applicationLists = $.applicationLists;
        this.compartmentId = $.compartmentId;
        this.decryptionProfiles = $.decryptionProfiles;
        this.decryptionRules = $.decryptionRules;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.ipAddressLists = $.ipAddressLists;
        this.mappedSecrets = $.mappedSecrets;
        this.securityRules = $.securityRules;
        this.urlLists = $.urlLists;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NetworkFirewallPolicyArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NetworkFirewallPolicyArgs $;

        public Builder() {
            $ = new NetworkFirewallPolicyArgs();
        }

        public Builder(NetworkFirewallPolicyArgs defaults) {
            $ = new NetworkFirewallPolicyArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param applicationLists (Updatable) Map defining application lists of the policy. The value of an entry is a list of &#34;applications&#34;, each consisting of a protocol identifier (such as TCP, UDP, or ICMP) and protocol-specific parameters (such as a port range). The associated key is the identifier by which the application list is referenced.
         * 
         * @return builder
         * 
         */
        public Builder applicationLists(@Nullable Output<List<NetworkFirewallPolicyApplicationListArgs>> applicationLists) {
            $.applicationLists = applicationLists;
            return this;
        }

        /**
         * @param applicationLists (Updatable) Map defining application lists of the policy. The value of an entry is a list of &#34;applications&#34;, each consisting of a protocol identifier (such as TCP, UDP, or ICMP) and protocol-specific parameters (such as a port range). The associated key is the identifier by which the application list is referenced.
         * 
         * @return builder
         * 
         */
        public Builder applicationLists(List<NetworkFirewallPolicyApplicationListArgs> applicationLists) {
            return applicationLists(Output.of(applicationLists));
        }

        /**
         * @param applicationLists (Updatable) Map defining application lists of the policy. The value of an entry is a list of &#34;applications&#34;, each consisting of a protocol identifier (such as TCP, UDP, or ICMP) and protocol-specific parameters (such as a port range). The associated key is the identifier by which the application list is referenced.
         * 
         * @return builder
         * 
         */
        public Builder applicationLists(NetworkFirewallPolicyApplicationListArgs... applicationLists) {
            return applicationLists(List.of(applicationLists));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the NetworkFirewall Policy.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the NetworkFirewall Policy.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param decryptionProfiles (Updatable) Map defining decryption profiles of the policy. The value of an entry is a decryption profile. The associated key is the identifier by which the decryption profile is referenced.
         * 
         * @return builder
         * 
         */
        public Builder decryptionProfiles(@Nullable Output<List<NetworkFirewallPolicyDecryptionProfileArgs>> decryptionProfiles) {
            $.decryptionProfiles = decryptionProfiles;
            return this;
        }

        /**
         * @param decryptionProfiles (Updatable) Map defining decryption profiles of the policy. The value of an entry is a decryption profile. The associated key is the identifier by which the decryption profile is referenced.
         * 
         * @return builder
         * 
         */
        public Builder decryptionProfiles(List<NetworkFirewallPolicyDecryptionProfileArgs> decryptionProfiles) {
            return decryptionProfiles(Output.of(decryptionProfiles));
        }

        /**
         * @param decryptionProfiles (Updatable) Map defining decryption profiles of the policy. The value of an entry is a decryption profile. The associated key is the identifier by which the decryption profile is referenced.
         * 
         * @return builder
         * 
         */
        public Builder decryptionProfiles(NetworkFirewallPolicyDecryptionProfileArgs... decryptionProfiles) {
            return decryptionProfiles(List.of(decryptionProfiles));
        }

        /**
         * @param decryptionRules (Updatable) List of Decryption Rules defining the behavior of the policy. The first rule with a matching condition determines the action taken upon network traffic.
         * 
         * @return builder
         * 
         */
        public Builder decryptionRules(@Nullable Output<List<NetworkFirewallPolicyDecryptionRuleArgs>> decryptionRules) {
            $.decryptionRules = decryptionRules;
            return this;
        }

        /**
         * @param decryptionRules (Updatable) List of Decryption Rules defining the behavior of the policy. The first rule with a matching condition determines the action taken upon network traffic.
         * 
         * @return builder
         * 
         */
        public Builder decryptionRules(List<NetworkFirewallPolicyDecryptionRuleArgs> decryptionRules) {
            return decryptionRules(Output.of(decryptionRules));
        }

        /**
         * @param decryptionRules (Updatable) List of Decryption Rules defining the behavior of the policy. The first rule with a matching condition determines the action taken upon network traffic.
         * 
         * @return builder
         * 
         */
        public Builder decryptionRules(NetworkFirewallPolicyDecryptionRuleArgs... decryptionRules) {
            return decryptionRules(List.of(decryptionRules));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) A user-friendly optional name for the firewall policy. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A user-friendly optional name for the firewall policy. Avoid entering confidential information.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param ipAddressLists (Updatable) Map defining IP address lists of the policy. The value of an entry is a list of IP addresses or prefixes in CIDR notation. The associated key is the identifier by which the IP address list is referenced.
         * 
         * @return builder
         * 
         */
        public Builder ipAddressLists(@Nullable Output<List<NetworkFirewallPolicyIpAddressListArgs>> ipAddressLists) {
            $.ipAddressLists = ipAddressLists;
            return this;
        }

        /**
         * @param ipAddressLists (Updatable) Map defining IP address lists of the policy. The value of an entry is a list of IP addresses or prefixes in CIDR notation. The associated key is the identifier by which the IP address list is referenced.
         * 
         * @return builder
         * 
         */
        public Builder ipAddressLists(List<NetworkFirewallPolicyIpAddressListArgs> ipAddressLists) {
            return ipAddressLists(Output.of(ipAddressLists));
        }

        /**
         * @param ipAddressLists (Updatable) Map defining IP address lists of the policy. The value of an entry is a list of IP addresses or prefixes in CIDR notation. The associated key is the identifier by which the IP address list is referenced.
         * 
         * @return builder
         * 
         */
        public Builder ipAddressLists(NetworkFirewallPolicyIpAddressListArgs... ipAddressLists) {
            return ipAddressLists(List.of(ipAddressLists));
        }

        /**
         * @param mappedSecrets (Updatable) Map defining secrets of the policy. The value of an entry is a &#34;mapped secret&#34; consisting of a purpose and source. The associated key is the identifier by which the mapped secret is referenced.
         * 
         * @return builder
         * 
         */
        public Builder mappedSecrets(@Nullable Output<List<NetworkFirewallPolicyMappedSecretArgs>> mappedSecrets) {
            $.mappedSecrets = mappedSecrets;
            return this;
        }

        /**
         * @param mappedSecrets (Updatable) Map defining secrets of the policy. The value of an entry is a &#34;mapped secret&#34; consisting of a purpose and source. The associated key is the identifier by which the mapped secret is referenced.
         * 
         * @return builder
         * 
         */
        public Builder mappedSecrets(List<NetworkFirewallPolicyMappedSecretArgs> mappedSecrets) {
            return mappedSecrets(Output.of(mappedSecrets));
        }

        /**
         * @param mappedSecrets (Updatable) Map defining secrets of the policy. The value of an entry is a &#34;mapped secret&#34; consisting of a purpose and source. The associated key is the identifier by which the mapped secret is referenced.
         * 
         * @return builder
         * 
         */
        public Builder mappedSecrets(NetworkFirewallPolicyMappedSecretArgs... mappedSecrets) {
            return mappedSecrets(List.of(mappedSecrets));
        }

        /**
         * @param securityRules (Updatable) List of Security Rules defining the behavior of the policy. The first rule with a matching condition determines the action taken upon network traffic.
         * 
         * @return builder
         * 
         */
        public Builder securityRules(@Nullable Output<List<NetworkFirewallPolicySecurityRuleArgs>> securityRules) {
            $.securityRules = securityRules;
            return this;
        }

        /**
         * @param securityRules (Updatable) List of Security Rules defining the behavior of the policy. The first rule with a matching condition determines the action taken upon network traffic.
         * 
         * @return builder
         * 
         */
        public Builder securityRules(List<NetworkFirewallPolicySecurityRuleArgs> securityRules) {
            return securityRules(Output.of(securityRules));
        }

        /**
         * @param securityRules (Updatable) List of Security Rules defining the behavior of the policy. The first rule with a matching condition determines the action taken upon network traffic.
         * 
         * @return builder
         * 
         */
        public Builder securityRules(NetworkFirewallPolicySecurityRuleArgs... securityRules) {
            return securityRules(List.of(securityRules));
        }

        /**
         * @param urlLists (Updatable) Map defining URL pattern lists of the policy. The value of an entry is a list of URL patterns. The associated key is the identifier by which the URL pattern list is referenced.
         * 
         * @return builder
         * 
         */
        public Builder urlLists(@Nullable Output<List<NetworkFirewallPolicyUrlListArgs>> urlLists) {
            $.urlLists = urlLists;
            return this;
        }

        /**
         * @param urlLists (Updatable) Map defining URL pattern lists of the policy. The value of an entry is a list of URL patterns. The associated key is the identifier by which the URL pattern list is referenced.
         * 
         * @return builder
         * 
         */
        public Builder urlLists(List<NetworkFirewallPolicyUrlListArgs> urlLists) {
            return urlLists(Output.of(urlLists));
        }

        /**
         * @param urlLists (Updatable) Map defining URL pattern lists of the policy. The value of an entry is a list of URL patterns. The associated key is the identifier by which the URL pattern list is referenced.
         * 
         * @return builder
         * 
         */
        public Builder urlLists(NetworkFirewallPolicyUrlListArgs... urlLists) {
            return urlLists(List.of(urlLists));
        }

        public NetworkFirewallPolicyArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            return $;
        }
    }

}