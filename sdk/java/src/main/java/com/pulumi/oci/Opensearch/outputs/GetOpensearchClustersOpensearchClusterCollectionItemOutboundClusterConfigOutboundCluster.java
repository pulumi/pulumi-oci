// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opensearch.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetOpensearchClustersOpensearchClusterCollectionItemOutboundClusterConfigOutboundCluster {
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    private String displayName;
    /**
     * @return Flag to indicate whether to skip the Outbound cluster during cross cluster search, if it is unavailable
     * 
     */
    private Boolean isSkipUnavailable;
    /**
     * @return Mode for the cross cluster connection
     * 
     */
    private String mode;
    /**
     * @return Sets the time interval between regular application-level ping messages that are sent to try and keep outbound cluster connections alive. If set to -1, application-level ping messages to this outbound cluster are not sent. If unset, application-level ping messages are sent according to the global transport.ping_schedule setting, which defaults to -1 meaning that pings are not sent.
     * 
     */
    private String pingSchedule;
    /**
     * @return OCID of the Outbound cluster
     * 
     */
    private String seedClusterId;

    private GetOpensearchClustersOpensearchClusterCollectionItemOutboundClusterConfigOutboundCluster() {}
    /**
     * @return A filter to return only resources that match the entire display name given.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Flag to indicate whether to skip the Outbound cluster during cross cluster search, if it is unavailable
     * 
     */
    public Boolean isSkipUnavailable() {
        return this.isSkipUnavailable;
    }
    /**
     * @return Mode for the cross cluster connection
     * 
     */
    public String mode() {
        return this.mode;
    }
    /**
     * @return Sets the time interval between regular application-level ping messages that are sent to try and keep outbound cluster connections alive. If set to -1, application-level ping messages to this outbound cluster are not sent. If unset, application-level ping messages are sent according to the global transport.ping_schedule setting, which defaults to -1 meaning that pings are not sent.
     * 
     */
    public String pingSchedule() {
        return this.pingSchedule;
    }
    /**
     * @return OCID of the Outbound cluster
     * 
     */
    public String seedClusterId() {
        return this.seedClusterId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetOpensearchClustersOpensearchClusterCollectionItemOutboundClusterConfigOutboundCluster defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String displayName;
        private Boolean isSkipUnavailable;
        private String mode;
        private String pingSchedule;
        private String seedClusterId;
        public Builder() {}
        public Builder(GetOpensearchClustersOpensearchClusterCollectionItemOutboundClusterConfigOutboundCluster defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.displayName = defaults.displayName;
    	      this.isSkipUnavailable = defaults.isSkipUnavailable;
    	      this.mode = defaults.mode;
    	      this.pingSchedule = defaults.pingSchedule;
    	      this.seedClusterId = defaults.seedClusterId;
        }

        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetOpensearchClustersOpensearchClusterCollectionItemOutboundClusterConfigOutboundCluster", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder isSkipUnavailable(Boolean isSkipUnavailable) {
            if (isSkipUnavailable == null) {
              throw new MissingRequiredPropertyException("GetOpensearchClustersOpensearchClusterCollectionItemOutboundClusterConfigOutboundCluster", "isSkipUnavailable");
            }
            this.isSkipUnavailable = isSkipUnavailable;
            return this;
        }
        @CustomType.Setter
        public Builder mode(String mode) {
            if (mode == null) {
              throw new MissingRequiredPropertyException("GetOpensearchClustersOpensearchClusterCollectionItemOutboundClusterConfigOutboundCluster", "mode");
            }
            this.mode = mode;
            return this;
        }
        @CustomType.Setter
        public Builder pingSchedule(String pingSchedule) {
            if (pingSchedule == null) {
              throw new MissingRequiredPropertyException("GetOpensearchClustersOpensearchClusterCollectionItemOutboundClusterConfigOutboundCluster", "pingSchedule");
            }
            this.pingSchedule = pingSchedule;
            return this;
        }
        @CustomType.Setter
        public Builder seedClusterId(String seedClusterId) {
            if (seedClusterId == null) {
              throw new MissingRequiredPropertyException("GetOpensearchClustersOpensearchClusterCollectionItemOutboundClusterConfigOutboundCluster", "seedClusterId");
            }
            this.seedClusterId = seedClusterId;
            return this;
        }
        public GetOpensearchClustersOpensearchClusterCollectionItemOutboundClusterConfigOutboundCluster build() {
            final var _resultValue = new GetOpensearchClustersOpensearchClusterCollectionItemOutboundClusterConfigOutboundCluster();
            _resultValue.displayName = displayName;
            _resultValue.isSkipUnavailable = isSkipUnavailable;
            _resultValue.mode = mode;
            _resultValue.pingSchedule = pingSchedule;
            _resultValue.seedClusterId = seedClusterId;
            return _resultValue;
        }
    }
}
