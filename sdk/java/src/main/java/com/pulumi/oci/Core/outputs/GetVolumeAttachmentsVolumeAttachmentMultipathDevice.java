// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetVolumeAttachmentsVolumeAttachmentMultipathDevice {
    /**
     * @return The volume&#39;s iSCSI IP address.  Example: `169.254.2.2`
     * 
     */
    private final String ipv4;
    /**
     * @return The target volume&#39;s iSCSI Qualified Name in the format defined by [RFC 3720](https://tools.ietf.org/html/rfc3720#page-32).  Example: `iqn.2015-12.com.oracleiaas:40b7ee03-883f-46c6-a951-63d2841d2195`
     * 
     */
    private final String iqn;
    /**
     * @return The volume&#39;s iSCSI port, usually port 860 or 3260.  Example: `3260`
     * 
     */
    private final Integer port;

    @CustomType.Constructor
    private GetVolumeAttachmentsVolumeAttachmentMultipathDevice(
        @CustomType.Parameter("ipv4") String ipv4,
        @CustomType.Parameter("iqn") String iqn,
        @CustomType.Parameter("port") Integer port) {
        this.ipv4 = ipv4;
        this.iqn = iqn;
        this.port = port;
    }

    /**
     * @return The volume&#39;s iSCSI IP address.  Example: `169.254.2.2`
     * 
     */
    public String ipv4() {
        return this.ipv4;
    }
    /**
     * @return The target volume&#39;s iSCSI Qualified Name in the format defined by [RFC 3720](https://tools.ietf.org/html/rfc3720#page-32).  Example: `iqn.2015-12.com.oracleiaas:40b7ee03-883f-46c6-a951-63d2841d2195`
     * 
     */
    public String iqn() {
        return this.iqn;
    }
    /**
     * @return The volume&#39;s iSCSI port, usually port 860 or 3260.  Example: `3260`
     * 
     */
    public Integer port() {
        return this.port;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetVolumeAttachmentsVolumeAttachmentMultipathDevice defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String ipv4;
        private String iqn;
        private Integer port;

        public Builder() {
    	      // Empty
        }

        public Builder(GetVolumeAttachmentsVolumeAttachmentMultipathDevice defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ipv4 = defaults.ipv4;
    	      this.iqn = defaults.iqn;
    	      this.port = defaults.port;
        }

        public Builder ipv4(String ipv4) {
            this.ipv4 = Objects.requireNonNull(ipv4);
            return this;
        }
        public Builder iqn(String iqn) {
            this.iqn = Objects.requireNonNull(iqn);
            return this;
        }
        public Builder port(Integer port) {
            this.port = Objects.requireNonNull(port);
            return this;
        }        public GetVolumeAttachmentsVolumeAttachmentMultipathDevice build() {
            return new GetVolumeAttachmentsVolumeAttachmentMultipathDevice(ipv4, iqn, port);
        }
    }
}
