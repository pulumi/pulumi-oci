// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class VmClusterNetworkVmNetworkNode {
    /**
     * @return (Updatable) The node host name.
     * 
     */
    private String hostname;
    /**
     * @return (Updatable) The node IP address.
     * 
     */
    private String ip;
    /**
     * @return (Updatable) The node virtual IP (VIP) address.
     * 
     */
    private @Nullable String vip;
    /**
     * @return (Updatable) The node virtual IP (VIP) host name.
     * 
     */
    private @Nullable String vipHostname;

    private VmClusterNetworkVmNetworkNode() {}
    /**
     * @return (Updatable) The node host name.
     * 
     */
    public String hostname() {
        return this.hostname;
    }
    /**
     * @return (Updatable) The node IP address.
     * 
     */
    public String ip() {
        return this.ip;
    }
    /**
     * @return (Updatable) The node virtual IP (VIP) address.
     * 
     */
    public Optional<String> vip() {
        return Optional.ofNullable(this.vip);
    }
    /**
     * @return (Updatable) The node virtual IP (VIP) host name.
     * 
     */
    public Optional<String> vipHostname() {
        return Optional.ofNullable(this.vipHostname);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(VmClusterNetworkVmNetworkNode defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String hostname;
        private String ip;
        private @Nullable String vip;
        private @Nullable String vipHostname;
        public Builder() {}
        public Builder(VmClusterNetworkVmNetworkNode defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.hostname = defaults.hostname;
    	      this.ip = defaults.ip;
    	      this.vip = defaults.vip;
    	      this.vipHostname = defaults.vipHostname;
        }

        @CustomType.Setter
        public Builder hostname(String hostname) {
            this.hostname = Objects.requireNonNull(hostname);
            return this;
        }
        @CustomType.Setter
        public Builder ip(String ip) {
            this.ip = Objects.requireNonNull(ip);
            return this;
        }
        @CustomType.Setter
        public Builder vip(@Nullable String vip) {
            this.vip = vip;
            return this;
        }
        @CustomType.Setter
        public Builder vipHostname(@Nullable String vipHostname) {
            this.vipHostname = vipHostname;
            return this;
        }
        public VmClusterNetworkVmNetworkNode build() {
            final var o = new VmClusterNetworkVmNetworkNode();
            o.hostname = hostname;
            o.ip = ip;
            o.vip = vip;
            o.vipHostname = vipHostname;
            return o;
        }
    }
}