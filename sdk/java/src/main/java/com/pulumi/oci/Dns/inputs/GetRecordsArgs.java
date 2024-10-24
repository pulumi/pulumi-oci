// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Dns.inputs.GetRecordsFilterArgs;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetRecordsArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetRecordsArgs Empty = new GetRecordsArgs();

    /**
     * The OCID of the compartment the zone belongs to.
     * 
     * This parameter is deprecated and should be omitted.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The OCID of the compartment the zone belongs to.
     * 
     * This parameter is deprecated and should be omitted.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * Search by domain. Will match any record whose domain (case-insensitive) equals the provided value.
     * 
     */
    @Import(name="domain")
    private @Nullable Output<String> domain;

    /**
     * @return Search by domain. Will match any record whose domain (case-insensitive) equals the provided value.
     * 
     */
    public Optional<Output<String>> domain() {
        return Optional.ofNullable(this.domain);
    }

    /**
     * Search by domain. Will match any record whose domain (case-insensitive) contains the provided value.
     * 
     */
    @Import(name="domainContains")
    private @Nullable Output<String> domainContains;

    /**
     * @return Search by domain. Will match any record whose domain (case-insensitive) contains the provided value.
     * 
     */
    public Optional<Output<String>> domainContains() {
        return Optional.ofNullable(this.domainContains);
    }

    @Import(name="filters")
    private @Nullable Output<List<GetRecordsFilterArgs>> filters;

    public Optional<Output<List<GetRecordsFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * Search by record type. Will match any record whose [type](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4) (case-insensitive) equals the provided value.
     * 
     */
    @Import(name="rtype")
    private @Nullable Output<String> rtype;

    /**
     * @return Search by record type. Will match any record whose [type](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4) (case-insensitive) equals the provided value.
     * 
     */
    public Optional<Output<String>> rtype() {
        return Optional.ofNullable(this.rtype);
    }

    /**
     * The field by which to sort records. Allowed values are: domain|rtype|ttl
     * 
     */
    @Import(name="sortBy")
    private @Nullable Output<String> sortBy;

    /**
     * @return The field by which to sort records. Allowed values are: domain|rtype|ttl
     * 
     */
    public Optional<Output<String>> sortBy() {
        return Optional.ofNullable(this.sortBy);
    }

    /**
     * The order to sort the resources. Allowed values are: ASC|DESC
     * 
     */
    @Import(name="sortOrder")
    private @Nullable Output<String> sortOrder;

    /**
     * @return The order to sort the resources. Allowed values are: ASC|DESC
     * 
     */
    public Optional<Output<String>> sortOrder() {
        return Optional.ofNullable(this.sortOrder);
    }

    /**
     * The name or OCID of the target zone.
     * 
     * @deprecated
     * The &#39;oci_dns_records&#39; resource has been deprecated. Please use &#39;oci_dns_rrsets&#39; instead.
     * 
     */
    @Deprecated /* The 'oci_dns_records' resource has been deprecated. Please use 'oci_dns_rrsets' instead. */
    @Import(name="zoneNameOrId", required=true)
    private Output<String> zoneNameOrId;

    /**
     * @return The name or OCID of the target zone.
     * 
     * @deprecated
     * The &#39;oci_dns_records&#39; resource has been deprecated. Please use &#39;oci_dns_rrsets&#39; instead.
     * 
     */
    @Deprecated /* The 'oci_dns_records' resource has been deprecated. Please use 'oci_dns_rrsets' instead. */
    public Output<String> zoneNameOrId() {
        return this.zoneNameOrId;
    }

    /**
     * The version of the zone for which data is requested.
     * 
     */
    @Import(name="zoneVersion")
    private @Nullable Output<String> zoneVersion;

    /**
     * @return The version of the zone for which data is requested.
     * 
     */
    public Optional<Output<String>> zoneVersion() {
        return Optional.ofNullable(this.zoneVersion);
    }

    private GetRecordsArgs() {}

    private GetRecordsArgs(GetRecordsArgs $) {
        this.compartmentId = $.compartmentId;
        this.domain = $.domain;
        this.domainContains = $.domainContains;
        this.filters = $.filters;
        this.rtype = $.rtype;
        this.sortBy = $.sortBy;
        this.sortOrder = $.sortOrder;
        this.zoneNameOrId = $.zoneNameOrId;
        this.zoneVersion = $.zoneVersion;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetRecordsArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetRecordsArgs $;

        public Builder() {
            $ = new GetRecordsArgs();
        }

        public Builder(GetRecordsArgs defaults) {
            $ = new GetRecordsArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId The OCID of the compartment the zone belongs to.
         * 
         * This parameter is deprecated and should be omitted.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the compartment the zone belongs to.
         * 
         * This parameter is deprecated and should be omitted.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param domain Search by domain. Will match any record whose domain (case-insensitive) equals the provided value.
         * 
         * @return builder
         * 
         */
        public Builder domain(@Nullable Output<String> domain) {
            $.domain = domain;
            return this;
        }

        /**
         * @param domain Search by domain. Will match any record whose domain (case-insensitive) equals the provided value.
         * 
         * @return builder
         * 
         */
        public Builder domain(String domain) {
            return domain(Output.of(domain));
        }

        /**
         * @param domainContains Search by domain. Will match any record whose domain (case-insensitive) contains the provided value.
         * 
         * @return builder
         * 
         */
        public Builder domainContains(@Nullable Output<String> domainContains) {
            $.domainContains = domainContains;
            return this;
        }

        /**
         * @param domainContains Search by domain. Will match any record whose domain (case-insensitive) contains the provided value.
         * 
         * @return builder
         * 
         */
        public Builder domainContains(String domainContains) {
            return domainContains(Output.of(domainContains));
        }

        public Builder filters(@Nullable Output<List<GetRecordsFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetRecordsFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetRecordsFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param rtype Search by record type. Will match any record whose [type](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4) (case-insensitive) equals the provided value.
         * 
         * @return builder
         * 
         */
        public Builder rtype(@Nullable Output<String> rtype) {
            $.rtype = rtype;
            return this;
        }

        /**
         * @param rtype Search by record type. Will match any record whose [type](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4) (case-insensitive) equals the provided value.
         * 
         * @return builder
         * 
         */
        public Builder rtype(String rtype) {
            return rtype(Output.of(rtype));
        }

        /**
         * @param sortBy The field by which to sort records. Allowed values are: domain|rtype|ttl
         * 
         * @return builder
         * 
         */
        public Builder sortBy(@Nullable Output<String> sortBy) {
            $.sortBy = sortBy;
            return this;
        }

        /**
         * @param sortBy The field by which to sort records. Allowed values are: domain|rtype|ttl
         * 
         * @return builder
         * 
         */
        public Builder sortBy(String sortBy) {
            return sortBy(Output.of(sortBy));
        }

        /**
         * @param sortOrder The order to sort the resources. Allowed values are: ASC|DESC
         * 
         * @return builder
         * 
         */
        public Builder sortOrder(@Nullable Output<String> sortOrder) {
            $.sortOrder = sortOrder;
            return this;
        }

        /**
         * @param sortOrder The order to sort the resources. Allowed values are: ASC|DESC
         * 
         * @return builder
         * 
         */
        public Builder sortOrder(String sortOrder) {
            return sortOrder(Output.of(sortOrder));
        }

        /**
         * @param zoneNameOrId The name or OCID of the target zone.
         * 
         * @return builder
         * 
         * @deprecated
         * The &#39;oci_dns_records&#39; resource has been deprecated. Please use &#39;oci_dns_rrsets&#39; instead.
         * 
         */
        @Deprecated /* The 'oci_dns_records' resource has been deprecated. Please use 'oci_dns_rrsets' instead. */
        public Builder zoneNameOrId(Output<String> zoneNameOrId) {
            $.zoneNameOrId = zoneNameOrId;
            return this;
        }

        /**
         * @param zoneNameOrId The name or OCID of the target zone.
         * 
         * @return builder
         * 
         * @deprecated
         * The &#39;oci_dns_records&#39; resource has been deprecated. Please use &#39;oci_dns_rrsets&#39; instead.
         * 
         */
        @Deprecated /* The 'oci_dns_records' resource has been deprecated. Please use 'oci_dns_rrsets' instead. */
        public Builder zoneNameOrId(String zoneNameOrId) {
            return zoneNameOrId(Output.of(zoneNameOrId));
        }

        /**
         * @param zoneVersion The version of the zone for which data is requested.
         * 
         * @return builder
         * 
         */
        public Builder zoneVersion(@Nullable Output<String> zoneVersion) {
            $.zoneVersion = zoneVersion;
            return this;
        }

        /**
         * @param zoneVersion The version of the zone for which data is requested.
         * 
         * @return builder
         * 
         */
        public Builder zoneVersion(String zoneVersion) {
            return zoneVersion(Output.of(zoneVersion));
        }

        public GetRecordsArgs build() {
            if ($.zoneNameOrId == null) {
                throw new MissingRequiredPropertyException("GetRecordsArgs", "zoneNameOrId");
            }
            return $;
        }
    }

}
