// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.ApmSynthetics.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDedicatedVantagePointDvpStackDetail {
    /**
     * @return Stack [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Resource Manager stack for dedicated vantage point.
     * 
     */
    private String dvpStackId;
    /**
     * @return Type of stack.
     * 
     */
    private String dvpStackType;
    /**
     * @return Stream [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Resource Manager stack for dedicated vantage point.
     * 
     */
    private String dvpStreamId;
    /**
     * @return Version of the dedicated vantage point.
     * 
     */
    private String dvpVersion;

    private GetDedicatedVantagePointDvpStackDetail() {}
    /**
     * @return Stack [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Resource Manager stack for dedicated vantage point.
     * 
     */
    public String dvpStackId() {
        return this.dvpStackId;
    }
    /**
     * @return Type of stack.
     * 
     */
    public String dvpStackType() {
        return this.dvpStackType;
    }
    /**
     * @return Stream [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Resource Manager stack for dedicated vantage point.
     * 
     */
    public String dvpStreamId() {
        return this.dvpStreamId;
    }
    /**
     * @return Version of the dedicated vantage point.
     * 
     */
    public String dvpVersion() {
        return this.dvpVersion;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDedicatedVantagePointDvpStackDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String dvpStackId;
        private String dvpStackType;
        private String dvpStreamId;
        private String dvpVersion;
        public Builder() {}
        public Builder(GetDedicatedVantagePointDvpStackDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dvpStackId = defaults.dvpStackId;
    	      this.dvpStackType = defaults.dvpStackType;
    	      this.dvpStreamId = defaults.dvpStreamId;
    	      this.dvpVersion = defaults.dvpVersion;
        }

        @CustomType.Setter
        public Builder dvpStackId(String dvpStackId) {
            this.dvpStackId = Objects.requireNonNull(dvpStackId);
            return this;
        }
        @CustomType.Setter
        public Builder dvpStackType(String dvpStackType) {
            this.dvpStackType = Objects.requireNonNull(dvpStackType);
            return this;
        }
        @CustomType.Setter
        public Builder dvpStreamId(String dvpStreamId) {
            this.dvpStreamId = Objects.requireNonNull(dvpStreamId);
            return this;
        }
        @CustomType.Setter
        public Builder dvpVersion(String dvpVersion) {
            this.dvpVersion = Objects.requireNonNull(dvpVersion);
            return this;
        }
        public GetDedicatedVantagePointDvpStackDetail build() {
            final var o = new GetDedicatedVantagePointDvpStackDetail();
            o.dvpStackId = dvpStackId;
            o.dvpStackType = dvpStackType;
            o.dvpStreamId = dvpStreamId;
            o.dvpVersion = dvpVersion;
            return o;
        }
    }
}