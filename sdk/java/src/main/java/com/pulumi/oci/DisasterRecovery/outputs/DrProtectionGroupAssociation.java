// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DisasterRecovery.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DrProtectionGroupAssociation {
    /**
     * @return The OCID of the peer (remote) DR Protection Group.  Example: `ocid1.drprotectiongroup.oc1.iad.exampleocid2`
     * 
     */
    private @Nullable String peerId;
    /**
     * @return The region of the peer (remote) DR Protection Group.  Example: `us-ashburn-1`
     * 
     */
    private @Nullable String peerRegion;
    /**
     * @return The role of this DR Protection Group.
     * 
     */
    private String role;

    private DrProtectionGroupAssociation() {}
    /**
     * @return The OCID of the peer (remote) DR Protection Group.  Example: `ocid1.drprotectiongroup.oc1.iad.exampleocid2`
     * 
     */
    public Optional<String> peerId() {
        return Optional.ofNullable(this.peerId);
    }
    /**
     * @return The region of the peer (remote) DR Protection Group.  Example: `us-ashburn-1`
     * 
     */
    public Optional<String> peerRegion() {
        return Optional.ofNullable(this.peerRegion);
    }
    /**
     * @return The role of this DR Protection Group.
     * 
     */
    public String role() {
        return this.role;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DrProtectionGroupAssociation defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String peerId;
        private @Nullable String peerRegion;
        private String role;
        public Builder() {}
        public Builder(DrProtectionGroupAssociation defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.peerId = defaults.peerId;
    	      this.peerRegion = defaults.peerRegion;
    	      this.role = defaults.role;
        }

        @CustomType.Setter
        public Builder peerId(@Nullable String peerId) {
            this.peerId = peerId;
            return this;
        }
        @CustomType.Setter
        public Builder peerRegion(@Nullable String peerRegion) {
            this.peerRegion = peerRegion;
            return this;
        }
        @CustomType.Setter
        public Builder role(String role) {
            this.role = Objects.requireNonNull(role);
            return this;
        }
        public DrProtectionGroupAssociation build() {
            final var o = new DrProtectionGroupAssociation();
            o.peerId = peerId;
            o.peerRegion = peerRegion;
            o.role = role;
            return o;
        }
    }
}