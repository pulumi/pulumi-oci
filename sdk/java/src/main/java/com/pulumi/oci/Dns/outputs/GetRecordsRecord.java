// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Boolean;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetRecordsRecord {
    /**
     * @return The OCID of the compartment the zone belongs to.
     * 
     * This parameter is deprecated and should be omitted.
     * 
     */
    private @Nullable String compartmentId;
    /**
     * @return Search by domain. Will match any record whose domain (case-insensitive) equals the provided value.
     * 
     * @deprecated
     * The &#39;oci_dns_record&#39; resource has been deprecated. Please use &#39;oci_dns_rrset&#39; instead.
     * 
     */
    @Deprecated /* The 'oci_dns_record' resource has been deprecated. Please use 'oci_dns_rrset' instead. */
    private String domain;
    /**
     * @return A Boolean flag indicating whether or not parts of the record are unable to be explicitly managed.
     * 
     */
    private Boolean isProtected;
    /**
     * @return The record&#39;s data, as whitespace-delimited tokens in type-specific presentation format. All RDATA is normalized and the returned presentation of your RDATA may differ from its initial input. For more information about RDATA, see [Supported DNS Resource Record Types](https://docs.cloud.oracle.com/iaas/Content/DNS/Reference/supporteddnsresource.htm)
     * 
     */
    private @Nullable String rdata;
    /**
     * @return A unique identifier for the record within its zone.
     * 
     */
    private String recordHash;
    /**
     * @return The latest version of the record&#39;s zone in which its RRSet differs from the preceding version.
     * 
     */
    private String rrsetVersion;
    /**
     * @return Search by record type. Will match any record whose [type](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4) (case-insensitive) equals the provided value.
     * 
     * @deprecated
     * The &#39;oci_dns_record&#39; resource has been deprecated. Please use &#39;oci_dns_rrset&#39; instead.
     * 
     */
    @Deprecated /* The 'oci_dns_record' resource has been deprecated. Please use 'oci_dns_rrset' instead. */
    private String rtype;
    /**
     * @return The Time To Live for the record, in seconds. Using a TTL lower than 30 seconds is not recommended.
     * 
     */
    private @Nullable Integer ttl;
    /**
     * @return The name or OCID of the target zone.
     * 
     * @deprecated
     * The &#39;oci_dns_record&#39; resource has been deprecated. Please use &#39;oci_dns_rrset&#39; instead.
     * 
     */
    @Deprecated /* The 'oci_dns_record' resource has been deprecated. Please use 'oci_dns_rrset' instead. */
    private String zoneNameOrId;

    private GetRecordsRecord() {}
    /**
     * @return The OCID of the compartment the zone belongs to.
     * 
     * This parameter is deprecated and should be omitted.
     * 
     */
    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    /**
     * @return Search by domain. Will match any record whose domain (case-insensitive) equals the provided value.
     * 
     * @deprecated
     * The &#39;oci_dns_record&#39; resource has been deprecated. Please use &#39;oci_dns_rrset&#39; instead.
     * 
     */
    @Deprecated /* The 'oci_dns_record' resource has been deprecated. Please use 'oci_dns_rrset' instead. */
    public String domain() {
        return this.domain;
    }
    /**
     * @return A Boolean flag indicating whether or not parts of the record are unable to be explicitly managed.
     * 
     */
    public Boolean isProtected() {
        return this.isProtected;
    }
    /**
     * @return The record&#39;s data, as whitespace-delimited tokens in type-specific presentation format. All RDATA is normalized and the returned presentation of your RDATA may differ from its initial input. For more information about RDATA, see [Supported DNS Resource Record Types](https://docs.cloud.oracle.com/iaas/Content/DNS/Reference/supporteddnsresource.htm)
     * 
     */
    public Optional<String> rdata() {
        return Optional.ofNullable(this.rdata);
    }
    /**
     * @return A unique identifier for the record within its zone.
     * 
     */
    public String recordHash() {
        return this.recordHash;
    }
    /**
     * @return The latest version of the record&#39;s zone in which its RRSet differs from the preceding version.
     * 
     */
    public String rrsetVersion() {
        return this.rrsetVersion;
    }
    /**
     * @return Search by record type. Will match any record whose [type](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4) (case-insensitive) equals the provided value.
     * 
     * @deprecated
     * The &#39;oci_dns_record&#39; resource has been deprecated. Please use &#39;oci_dns_rrset&#39; instead.
     * 
     */
    @Deprecated /* The 'oci_dns_record' resource has been deprecated. Please use 'oci_dns_rrset' instead. */
    public String rtype() {
        return this.rtype;
    }
    /**
     * @return The Time To Live for the record, in seconds. Using a TTL lower than 30 seconds is not recommended.
     * 
     */
    public Optional<Integer> ttl() {
        return Optional.ofNullable(this.ttl);
    }
    /**
     * @return The name or OCID of the target zone.
     * 
     * @deprecated
     * The &#39;oci_dns_record&#39; resource has been deprecated. Please use &#39;oci_dns_rrset&#39; instead.
     * 
     */
    @Deprecated /* The 'oci_dns_record' resource has been deprecated. Please use 'oci_dns_rrset' instead. */
    public String zoneNameOrId() {
        return this.zoneNameOrId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetRecordsRecord defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private @Nullable String compartmentId;
        private String domain;
        private Boolean isProtected;
        private @Nullable String rdata;
        private String recordHash;
        private String rrsetVersion;
        private String rtype;
        private @Nullable Integer ttl;
        private String zoneNameOrId;
        public Builder() {}
        public Builder(GetRecordsRecord defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.domain = defaults.domain;
    	      this.isProtected = defaults.isProtected;
    	      this.rdata = defaults.rdata;
    	      this.recordHash = defaults.recordHash;
    	      this.rrsetVersion = defaults.rrsetVersion;
    	      this.rtype = defaults.rtype;
    	      this.ttl = defaults.ttl;
    	      this.zoneNameOrId = defaults.zoneNameOrId;
        }

        @CustomType.Setter
        public Builder compartmentId(@Nullable String compartmentId) {

            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder domain(String domain) {
            if (domain == null) {
              throw new MissingRequiredPropertyException("GetRecordsRecord", "domain");
            }
            this.domain = domain;
            return this;
        }
        @CustomType.Setter
        public Builder isProtected(Boolean isProtected) {
            if (isProtected == null) {
              throw new MissingRequiredPropertyException("GetRecordsRecord", "isProtected");
            }
            this.isProtected = isProtected;
            return this;
        }
        @CustomType.Setter
        public Builder rdata(@Nullable String rdata) {

            this.rdata = rdata;
            return this;
        }
        @CustomType.Setter
        public Builder recordHash(String recordHash) {
            if (recordHash == null) {
              throw new MissingRequiredPropertyException("GetRecordsRecord", "recordHash");
            }
            this.recordHash = recordHash;
            return this;
        }
        @CustomType.Setter
        public Builder rrsetVersion(String rrsetVersion) {
            if (rrsetVersion == null) {
              throw new MissingRequiredPropertyException("GetRecordsRecord", "rrsetVersion");
            }
            this.rrsetVersion = rrsetVersion;
            return this;
        }
        @CustomType.Setter
        public Builder rtype(String rtype) {
            if (rtype == null) {
              throw new MissingRequiredPropertyException("GetRecordsRecord", "rtype");
            }
            this.rtype = rtype;
            return this;
        }
        @CustomType.Setter
        public Builder ttl(@Nullable Integer ttl) {

            this.ttl = ttl;
            return this;
        }
        @CustomType.Setter
        public Builder zoneNameOrId(String zoneNameOrId) {
            if (zoneNameOrId == null) {
              throw new MissingRequiredPropertyException("GetRecordsRecord", "zoneNameOrId");
            }
            this.zoneNameOrId = zoneNameOrId;
            return this;
        }
        public GetRecordsRecord build() {
            final var _resultValue = new GetRecordsRecord();
            _resultValue.compartmentId = compartmentId;
            _resultValue.domain = domain;
            _resultValue.isProtected = isProtected;
            _resultValue.rdata = rdata;
            _resultValue.recordHash = recordHash;
            _resultValue.rrsetVersion = rrsetVersion;
            _resultValue.rtype = rtype;
            _resultValue.ttl = ttl;
            _resultValue.zoneNameOrId = zoneNameOrId;
            return _resultValue;
        }
    }
}
