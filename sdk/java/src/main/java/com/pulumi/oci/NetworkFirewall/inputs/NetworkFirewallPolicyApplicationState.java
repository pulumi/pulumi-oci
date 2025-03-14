// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.NetworkFirewall.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class NetworkFirewallPolicyApplicationState extends com.pulumi.resources.ResourceArgs {

    public static final NetworkFirewallPolicyApplicationState Empty = new NetworkFirewallPolicyApplicationState();

    /**
     * (Updatable) The value of the ICMP/ICMP_V6 message Code (subtype) field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
     * 
     */
    @Import(name="icmpCode")
    private @Nullable Output<Integer> icmpCode;

    /**
     * @return (Updatable) The value of the ICMP/ICMP_V6 message Code (subtype) field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
     * 
     */
    public Optional<Output<Integer>> icmpCode() {
        return Optional.ofNullable(this.icmpCode);
    }

    /**
     * (Updatable) The value of the ICMP/IMCP_V6 message Type field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
     * 
     */
    @Import(name="icmpType")
    private @Nullable Output<Integer> icmpType;

    /**
     * @return (Updatable) The value of the ICMP/IMCP_V6 message Type field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
     * 
     */
    public Optional<Output<Integer>> icmpType() {
        return Optional.ofNullable(this.icmpType);
    }

    /**
     * Name of the application
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return Name of the application
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * Unique Network Firewall Policy identifier
     * 
     */
    @Import(name="networkFirewallPolicyId")
    private @Nullable Output<String> networkFirewallPolicyId;

    /**
     * @return Unique Network Firewall Policy identifier
     * 
     */
    public Optional<Output<String>> networkFirewallPolicyId() {
        return Optional.ofNullable(this.networkFirewallPolicyId);
    }

    /**
     * OCID of the Network Firewall Policy this application belongs to.
     * 
     */
    @Import(name="parentResourceId")
    private @Nullable Output<String> parentResourceId;

    /**
     * @return OCID of the Network Firewall Policy this application belongs to.
     * 
     */
    public Optional<Output<String>> parentResourceId() {
        return Optional.ofNullable(this.parentResourceId);
    }

    /**
     * Describes the type of application. The accepted values are - * ICMP * ICMP_V6
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="type")
    private @Nullable Output<String> type;

    /**
     * @return Describes the type of application. The accepted values are - * ICMP * ICMP_V6
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<String>> type() {
        return Optional.ofNullable(this.type);
    }

    private NetworkFirewallPolicyApplicationState() {}

    private NetworkFirewallPolicyApplicationState(NetworkFirewallPolicyApplicationState $) {
        this.icmpCode = $.icmpCode;
        this.icmpType = $.icmpType;
        this.name = $.name;
        this.networkFirewallPolicyId = $.networkFirewallPolicyId;
        this.parentResourceId = $.parentResourceId;
        this.type = $.type;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(NetworkFirewallPolicyApplicationState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private NetworkFirewallPolicyApplicationState $;

        public Builder() {
            $ = new NetworkFirewallPolicyApplicationState();
        }

        public Builder(NetworkFirewallPolicyApplicationState defaults) {
            $ = new NetworkFirewallPolicyApplicationState(Objects.requireNonNull(defaults));
        }

        /**
         * @param icmpCode (Updatable) The value of the ICMP/ICMP_V6 message Code (subtype) field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
         * 
         * @return builder
         * 
         */
        public Builder icmpCode(@Nullable Output<Integer> icmpCode) {
            $.icmpCode = icmpCode;
            return this;
        }

        /**
         * @param icmpCode (Updatable) The value of the ICMP/ICMP_V6 message Code (subtype) field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
         * 
         * @return builder
         * 
         */
        public Builder icmpCode(Integer icmpCode) {
            return icmpCode(Output.of(icmpCode));
        }

        /**
         * @param icmpType (Updatable) The value of the ICMP/IMCP_V6 message Type field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
         * 
         * @return builder
         * 
         */
        public Builder icmpType(@Nullable Output<Integer> icmpType) {
            $.icmpType = icmpType;
            return this;
        }

        /**
         * @param icmpType (Updatable) The value of the ICMP/IMCP_V6 message Type field as defined by [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html#section-2.1).
         * 
         * @return builder
         * 
         */
        public Builder icmpType(Integer icmpType) {
            return icmpType(Output.of(icmpType));
        }

        /**
         * @param name Name of the application
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Name of the application
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param networkFirewallPolicyId Unique Network Firewall Policy identifier
         * 
         * @return builder
         * 
         */
        public Builder networkFirewallPolicyId(@Nullable Output<String> networkFirewallPolicyId) {
            $.networkFirewallPolicyId = networkFirewallPolicyId;
            return this;
        }

        /**
         * @param networkFirewallPolicyId Unique Network Firewall Policy identifier
         * 
         * @return builder
         * 
         */
        public Builder networkFirewallPolicyId(String networkFirewallPolicyId) {
            return networkFirewallPolicyId(Output.of(networkFirewallPolicyId));
        }

        /**
         * @param parentResourceId OCID of the Network Firewall Policy this application belongs to.
         * 
         * @return builder
         * 
         */
        public Builder parentResourceId(@Nullable Output<String> parentResourceId) {
            $.parentResourceId = parentResourceId;
            return this;
        }

        /**
         * @param parentResourceId OCID of the Network Firewall Policy this application belongs to.
         * 
         * @return builder
         * 
         */
        public Builder parentResourceId(String parentResourceId) {
            return parentResourceId(Output.of(parentResourceId));
        }

        /**
         * @param type Describes the type of application. The accepted values are - * ICMP * ICMP_V6
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder type(@Nullable Output<String> type) {
            $.type = type;
            return this;
        }

        /**
         * @param type Describes the type of application. The accepted values are - * ICMP * ICMP_V6
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder type(String type) {
            return type(Output.of(type));
        }

        public NetworkFirewallPolicyApplicationState build() {
            return $;
        }
    }

}
