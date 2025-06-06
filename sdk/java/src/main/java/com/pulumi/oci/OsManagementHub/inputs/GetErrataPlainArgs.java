// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsManagementHub.inputs;

import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.OsManagementHub.inputs.GetErrataFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetErrataPlainArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetErrataPlainArgs Empty = new GetErrataPlainArgs();

    /**
     * The advisory severity.
     * 
     */
    @Import(name="advisorySeverities")
    private @Nullable List<String> advisorySeverities;

    /**
     * @return The advisory severity.
     * 
     */
    public Optional<List<String>> advisorySeverities() {
        return Optional.ofNullable(this.advisorySeverities);
    }

    /**
     * A filter to return only errata that match the given advisory types.
     * 
     */
    @Import(name="advisoryTypes")
    private @Nullable List<String> advisoryTypes;

    /**
     * @return A filter to return only errata that match the given advisory types.
     * 
     */
    public Optional<List<String>> advisoryTypes() {
        return Optional.ofNullable(this.advisoryTypes);
    }

    /**
     * A filter to return only packages that match the given update classification type.
     * 
     */
    @Import(name="classificationTypes")
    private @Nullable List<String> classificationTypes;

    /**
     * @return A filter to return only packages that match the given update classification type.
     * 
     */
    public Optional<List<String>> classificationTypes() {
        return Optional.ofNullable(this.classificationTypes);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This parameter is required and returns only resources contained within the specified compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private String compartmentId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This parameter is required and returns only resources contained within the specified compartment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }

    @Import(name="filters")
    private @Nullable List<GetErrataFilter> filters;

    public Optional<List<GetErrataFilter>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * A filter to return resources that may partially match the erratum name given.
     * 
     */
    @Import(name="nameContains")
    private @Nullable String nameContains;

    /**
     * @return A filter to return resources that may partially match the erratum name given.
     * 
     */
    public Optional<String> nameContains() {
        return Optional.ofNullable(this.nameContains);
    }

    /**
     * The assigned erratum name. It&#39;s unique and not changeable.  Example: `ELSA-2020-5804`
     * 
     */
    @Import(name="names")
    private @Nullable List<String> names;

    /**
     * @return The assigned erratum name. It&#39;s unique and not changeable.  Example: `ELSA-2020-5804`
     * 
     */
    public Optional<List<String>> names() {
        return Optional.ofNullable(this.names);
    }

    /**
     * A filter to return only resources that match the given operating system family.
     * 
     */
    @Import(name="osFamily")
    private @Nullable String osFamily;

    /**
     * @return A filter to return only resources that match the given operating system family.
     * 
     */
    public Optional<String> osFamily() {
        return Optional.ofNullable(this.osFamily);
    }

    /**
     * The issue date before which to list all errata, in ISO 8601 format  Example: 2017-07-14T02:40:00.000Z
     * 
     */
    @Import(name="timeIssueDateEnd")
    private @Nullable String timeIssueDateEnd;

    /**
     * @return The issue date before which to list all errata, in ISO 8601 format  Example: 2017-07-14T02:40:00.000Z
     * 
     */
    public Optional<String> timeIssueDateEnd() {
        return Optional.ofNullable(this.timeIssueDateEnd);
    }

    /**
     * The issue date after which to list all errata, in ISO 8601 format  Example: 2017-07-14T02:40:00.000Z
     * 
     */
    @Import(name="timeIssueDateStart")
    private @Nullable String timeIssueDateStart;

    /**
     * @return The issue date after which to list all errata, in ISO 8601 format  Example: 2017-07-14T02:40:00.000Z
     * 
     */
    public Optional<String> timeIssueDateStart() {
        return Optional.ofNullable(this.timeIssueDateStart);
    }

    private GetErrataPlainArgs() {}

    private GetErrataPlainArgs(GetErrataPlainArgs $) {
        this.advisorySeverities = $.advisorySeverities;
        this.advisoryTypes = $.advisoryTypes;
        this.classificationTypes = $.classificationTypes;
        this.compartmentId = $.compartmentId;
        this.filters = $.filters;
        this.nameContains = $.nameContains;
        this.names = $.names;
        this.osFamily = $.osFamily;
        this.timeIssueDateEnd = $.timeIssueDateEnd;
        this.timeIssueDateStart = $.timeIssueDateStart;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetErrataPlainArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetErrataPlainArgs $;

        public Builder() {
            $ = new GetErrataPlainArgs();
        }

        public Builder(GetErrataPlainArgs defaults) {
            $ = new GetErrataPlainArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param advisorySeverities The advisory severity.
         * 
         * @return builder
         * 
         */
        public Builder advisorySeverities(@Nullable List<String> advisorySeverities) {
            $.advisorySeverities = advisorySeverities;
            return this;
        }

        /**
         * @param advisorySeverities The advisory severity.
         * 
         * @return builder
         * 
         */
        public Builder advisorySeverities(String... advisorySeverities) {
            return advisorySeverities(List.of(advisorySeverities));
        }

        /**
         * @param advisoryTypes A filter to return only errata that match the given advisory types.
         * 
         * @return builder
         * 
         */
        public Builder advisoryTypes(@Nullable List<String> advisoryTypes) {
            $.advisoryTypes = advisoryTypes;
            return this;
        }

        /**
         * @param advisoryTypes A filter to return only errata that match the given advisory types.
         * 
         * @return builder
         * 
         */
        public Builder advisoryTypes(String... advisoryTypes) {
            return advisoryTypes(List.of(advisoryTypes));
        }

        /**
         * @param classificationTypes A filter to return only packages that match the given update classification type.
         * 
         * @return builder
         * 
         */
        public Builder classificationTypes(@Nullable List<String> classificationTypes) {
            $.classificationTypes = classificationTypes;
            return this;
        }

        /**
         * @param classificationTypes A filter to return only packages that match the given update classification type.
         * 
         * @return builder
         * 
         */
        public Builder classificationTypes(String... classificationTypes) {
            return classificationTypes(List.of(classificationTypes));
        }

        /**
         * @param compartmentId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment. This parameter is required and returns only resources contained within the specified compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        public Builder filters(@Nullable List<GetErrataFilter> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(GetErrataFilter... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param nameContains A filter to return resources that may partially match the erratum name given.
         * 
         * @return builder
         * 
         */
        public Builder nameContains(@Nullable String nameContains) {
            $.nameContains = nameContains;
            return this;
        }

        /**
         * @param names The assigned erratum name. It&#39;s unique and not changeable.  Example: `ELSA-2020-5804`
         * 
         * @return builder
         * 
         */
        public Builder names(@Nullable List<String> names) {
            $.names = names;
            return this;
        }

        /**
         * @param names The assigned erratum name. It&#39;s unique and not changeable.  Example: `ELSA-2020-5804`
         * 
         * @return builder
         * 
         */
        public Builder names(String... names) {
            return names(List.of(names));
        }

        /**
         * @param osFamily A filter to return only resources that match the given operating system family.
         * 
         * @return builder
         * 
         */
        public Builder osFamily(@Nullable String osFamily) {
            $.osFamily = osFamily;
            return this;
        }

        /**
         * @param timeIssueDateEnd The issue date before which to list all errata, in ISO 8601 format  Example: 2017-07-14T02:40:00.000Z
         * 
         * @return builder
         * 
         */
        public Builder timeIssueDateEnd(@Nullable String timeIssueDateEnd) {
            $.timeIssueDateEnd = timeIssueDateEnd;
            return this;
        }

        /**
         * @param timeIssueDateStart The issue date after which to list all errata, in ISO 8601 format  Example: 2017-07-14T02:40:00.000Z
         * 
         * @return builder
         * 
         */
        public Builder timeIssueDateStart(@Nullable String timeIssueDateStart) {
            $.timeIssueDateStart = timeIssueDateStart;
            return this;
        }

        public GetErrataPlainArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("GetErrataPlainArgs", "compartmentId");
            }
            return $;
        }
    }

}
