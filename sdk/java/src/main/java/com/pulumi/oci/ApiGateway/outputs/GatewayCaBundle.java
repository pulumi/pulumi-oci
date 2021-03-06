// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApiGateway.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GatewayCaBundle {
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    private final @Nullable String caBundleId;
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    private final @Nullable String certificateAuthorityId;
    /**
     * @return (Updatable) Type of the Response Cache.
     * 
     */
    private final String type;

    @CustomType.Constructor
    private GatewayCaBundle(
        @CustomType.Parameter("caBundleId") @Nullable String caBundleId,
        @CustomType.Parameter("certificateAuthorityId") @Nullable String certificateAuthorityId,
        @CustomType.Parameter("type") String type) {
        this.caBundleId = caBundleId;
        this.certificateAuthorityId = certificateAuthorityId;
        this.type = type;
    }

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    public Optional<String> caBundleId() {
        return Optional.ofNullable(this.caBundleId);
    }
    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
     * 
     */
    public Optional<String> certificateAuthorityId() {
        return Optional.ofNullable(this.certificateAuthorityId);
    }
    /**
     * @return (Updatable) Type of the Response Cache.
     * 
     */
    public String type() {
        return this.type;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GatewayCaBundle defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String caBundleId;
        private @Nullable String certificateAuthorityId;
        private String type;

        public Builder() {
    	      // Empty
        }

        public Builder(GatewayCaBundle defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.caBundleId = defaults.caBundleId;
    	      this.certificateAuthorityId = defaults.certificateAuthorityId;
    	      this.type = defaults.type;
        }

        public Builder caBundleId(@Nullable String caBundleId) {
            this.caBundleId = caBundleId;
            return this;
        }
        public Builder certificateAuthorityId(@Nullable String certificateAuthorityId) {
            this.certificateAuthorityId = certificateAuthorityId;
            return this;
        }
        public Builder type(String type) {
            this.type = Objects.requireNonNull(type);
            return this;
        }        public GatewayCaBundle build() {
            return new GatewayCaBundle(caBundleId, certificateAuthorityId, type);
        }
    }
}
