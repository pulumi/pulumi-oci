// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalExadataStorageServerOpenAlertHistoryAlert;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetExternalExadataStorageServerOpenAlertHistoryResult {
    /**
     * @return A list of open alerts.
     * 
     */
    private List<GetExternalExadataStorageServerOpenAlertHistoryAlert> alerts;
    private String externalExadataStorageServerId;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;

    private GetExternalExadataStorageServerOpenAlertHistoryResult() {}
    /**
     * @return A list of open alerts.
     * 
     */
    public List<GetExternalExadataStorageServerOpenAlertHistoryAlert> alerts() {
        return this.alerts;
    }
    public String externalExadataStorageServerId() {
        return this.externalExadataStorageServerId;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalExadataStorageServerOpenAlertHistoryResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetExternalExadataStorageServerOpenAlertHistoryAlert> alerts;
        private String externalExadataStorageServerId;
        private String id;
        public Builder() {}
        public Builder(GetExternalExadataStorageServerOpenAlertHistoryResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.alerts = defaults.alerts;
    	      this.externalExadataStorageServerId = defaults.externalExadataStorageServerId;
    	      this.id = defaults.id;
        }

        @CustomType.Setter
        public Builder alerts(List<GetExternalExadataStorageServerOpenAlertHistoryAlert> alerts) {
            this.alerts = Objects.requireNonNull(alerts);
            return this;
        }
        public Builder alerts(GetExternalExadataStorageServerOpenAlertHistoryAlert... alerts) {
            return alerts(List.of(alerts));
        }
        @CustomType.Setter
        public Builder externalExadataStorageServerId(String externalExadataStorageServerId) {
            this.externalExadataStorageServerId = Objects.requireNonNull(externalExadataStorageServerId);
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public GetExternalExadataStorageServerOpenAlertHistoryResult build() {
            final var o = new GetExternalExadataStorageServerOpenAlertHistoryResult();
            o.alerts = alerts;
            o.externalExadataStorageServerId = externalExadataStorageServerId;
            o.id = id;
            return o;
        }
    }
}