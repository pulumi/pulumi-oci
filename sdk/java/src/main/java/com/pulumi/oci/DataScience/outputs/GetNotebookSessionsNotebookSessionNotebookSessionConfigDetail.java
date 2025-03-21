// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DataScience.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DataScience.outputs.GetNotebookSessionsNotebookSessionNotebookSessionConfigDetailNotebookSessionShapeConfigDetail;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetNotebookSessionsNotebookSessionNotebookSessionConfigDetail {
    /**
     * @return A notebook session instance is provided with a block storage volume. This specifies the size of the volume in GBs.
     * 
     */
    private Integer blockStorageSizeInGbs;
    /**
     * @return Details for the notebook session shape configuration.
     * 
     */
    private List<GetNotebookSessionsNotebookSessionNotebookSessionConfigDetailNotebookSessionShapeConfigDetail> notebookSessionShapeConfigDetails;
    /**
     * @return The OCID of a Data Science private endpoint.
     * 
     */
    private String privateEndpointId;
    /**
     * @return The shape used to launch the notebook session compute instance.  The list of available shapes in a given compartment can be retrieved using the `ListNotebookSessionShapes` endpoint.
     * 
     */
    private String shape;
    /**
     * @return A notebook session instance is provided with a VNIC for network access.  This specifies the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet to create a VNIC in.  The subnet should be in a VCN with a NAT gateway for egress to the internet.
     * 
     */
    private String subnetId;

    private GetNotebookSessionsNotebookSessionNotebookSessionConfigDetail() {}
    /**
     * @return A notebook session instance is provided with a block storage volume. This specifies the size of the volume in GBs.
     * 
     */
    public Integer blockStorageSizeInGbs() {
        return this.blockStorageSizeInGbs;
    }
    /**
     * @return Details for the notebook session shape configuration.
     * 
     */
    public List<GetNotebookSessionsNotebookSessionNotebookSessionConfigDetailNotebookSessionShapeConfigDetail> notebookSessionShapeConfigDetails() {
        return this.notebookSessionShapeConfigDetails;
    }
    /**
     * @return The OCID of a Data Science private endpoint.
     * 
     */
    public String privateEndpointId() {
        return this.privateEndpointId;
    }
    /**
     * @return The shape used to launch the notebook session compute instance.  The list of available shapes in a given compartment can be retrieved using the `ListNotebookSessionShapes` endpoint.
     * 
     */
    public String shape() {
        return this.shape;
    }
    /**
     * @return A notebook session instance is provided with a VNIC for network access.  This specifies the [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet to create a VNIC in.  The subnet should be in a VCN with a NAT gateway for egress to the internet.
     * 
     */
    public String subnetId() {
        return this.subnetId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetNotebookSessionsNotebookSessionNotebookSessionConfigDetail defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer blockStorageSizeInGbs;
        private List<GetNotebookSessionsNotebookSessionNotebookSessionConfigDetailNotebookSessionShapeConfigDetail> notebookSessionShapeConfigDetails;
        private String privateEndpointId;
        private String shape;
        private String subnetId;
        public Builder() {}
        public Builder(GetNotebookSessionsNotebookSessionNotebookSessionConfigDetail defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.blockStorageSizeInGbs = defaults.blockStorageSizeInGbs;
    	      this.notebookSessionShapeConfigDetails = defaults.notebookSessionShapeConfigDetails;
    	      this.privateEndpointId = defaults.privateEndpointId;
    	      this.shape = defaults.shape;
    	      this.subnetId = defaults.subnetId;
        }

        @CustomType.Setter
        public Builder blockStorageSizeInGbs(Integer blockStorageSizeInGbs) {
            if (blockStorageSizeInGbs == null) {
              throw new MissingRequiredPropertyException("GetNotebookSessionsNotebookSessionNotebookSessionConfigDetail", "blockStorageSizeInGbs");
            }
            this.blockStorageSizeInGbs = blockStorageSizeInGbs;
            return this;
        }
        @CustomType.Setter
        public Builder notebookSessionShapeConfigDetails(List<GetNotebookSessionsNotebookSessionNotebookSessionConfigDetailNotebookSessionShapeConfigDetail> notebookSessionShapeConfigDetails) {
            if (notebookSessionShapeConfigDetails == null) {
              throw new MissingRequiredPropertyException("GetNotebookSessionsNotebookSessionNotebookSessionConfigDetail", "notebookSessionShapeConfigDetails");
            }
            this.notebookSessionShapeConfigDetails = notebookSessionShapeConfigDetails;
            return this;
        }
        public Builder notebookSessionShapeConfigDetails(GetNotebookSessionsNotebookSessionNotebookSessionConfigDetailNotebookSessionShapeConfigDetail... notebookSessionShapeConfigDetails) {
            return notebookSessionShapeConfigDetails(List.of(notebookSessionShapeConfigDetails));
        }
        @CustomType.Setter
        public Builder privateEndpointId(String privateEndpointId) {
            if (privateEndpointId == null) {
              throw new MissingRequiredPropertyException("GetNotebookSessionsNotebookSessionNotebookSessionConfigDetail", "privateEndpointId");
            }
            this.privateEndpointId = privateEndpointId;
            return this;
        }
        @CustomType.Setter
        public Builder shape(String shape) {
            if (shape == null) {
              throw new MissingRequiredPropertyException("GetNotebookSessionsNotebookSessionNotebookSessionConfigDetail", "shape");
            }
            this.shape = shape;
            return this;
        }
        @CustomType.Setter
        public Builder subnetId(String subnetId) {
            if (subnetId == null) {
              throw new MissingRequiredPropertyException("GetNotebookSessionsNotebookSessionNotebookSessionConfigDetail", "subnetId");
            }
            this.subnetId = subnetId;
            return this;
        }
        public GetNotebookSessionsNotebookSessionNotebookSessionConfigDetail build() {
            final var _resultValue = new GetNotebookSessionsNotebookSessionNotebookSessionConfigDetail();
            _resultValue.blockStorageSizeInGbs = blockStorageSizeInGbs;
            _resultValue.notebookSessionShapeConfigDetails = notebookSessionShapeConfigDetails;
            _resultValue.privateEndpointId = privateEndpointId;
            _resultValue.shape = shape;
            _resultValue.subnetId = subnetId;
            return _resultValue;
        }
    }
}
