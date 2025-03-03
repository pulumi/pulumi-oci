// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.inputs.GetManagedDatabasesDatabaseParametersFilterArgs;
import java.lang.Boolean;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class GetManagedDatabasesDatabaseParametersArgs extends com.pulumi.resources.InvokeArgs {

    public static final GetManagedDatabasesDatabaseParametersArgs Empty = new GetManagedDatabasesDatabaseParametersArgs();

    @Import(name="filters")
    private @Nullable Output<List<GetManagedDatabasesDatabaseParametersFilterArgs>> filters;

    public Optional<Output<List<GetManagedDatabasesDatabaseParametersFilterArgs>>> filters() {
        return Optional.ofNullable(this.filters);
    }

    /**
     * When true, results include a list of valid values for parameters (if applicable).
     * 
     */
    @Import(name="isAllowedValuesIncluded")
    private @Nullable Output<Boolean> isAllowedValuesIncluded;

    /**
     * @return When true, results include a list of valid values for parameters (if applicable).
     * 
     */
    public Optional<Output<Boolean>> isAllowedValuesIncluded() {
        return Optional.ofNullable(this.isAllowedValuesIncluded);
    }

    /**
     * The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    @Import(name="managedDatabaseId", required=true)
    private Output<String> managedDatabaseId;

    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    public Output<String> managedDatabaseId() {
        return this.managedDatabaseId;
    }

    /**
     * A filter to return all parameters that have the text given in their names.
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return A filter to return all parameters that have the text given in their names.
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * The OCID of the Named Credential.
     * 
     */
    @Import(name="opcNamedCredentialId")
    private @Nullable Output<String> opcNamedCredentialId;

    /**
     * @return The OCID of the Named Credential.
     * 
     */
    public Optional<Output<String>> opcNamedCredentialId() {
        return Optional.ofNullable(this.opcNamedCredentialId);
    }

    /**
     * The source used to list database parameters. `CURRENT` is used to get the database parameters that are currently in effect for the database instance. `SPFILE` is used to list parameters from the server parameter file. Default is `CURRENT`.
     * 
     */
    @Import(name="source")
    private @Nullable Output<String> source;

    /**
     * @return The source used to list database parameters. `CURRENT` is used to get the database parameters that are currently in effect for the database instance. `SPFILE` is used to list parameters from the server parameter file. Default is `CURRENT`.
     * 
     */
    public Optional<Output<String>> source() {
        return Optional.ofNullable(this.source);
    }

    private GetManagedDatabasesDatabaseParametersArgs() {}

    private GetManagedDatabasesDatabaseParametersArgs(GetManagedDatabasesDatabaseParametersArgs $) {
        this.filters = $.filters;
        this.isAllowedValuesIncluded = $.isAllowedValuesIncluded;
        this.managedDatabaseId = $.managedDatabaseId;
        this.name = $.name;
        this.opcNamedCredentialId = $.opcNamedCredentialId;
        this.source = $.source;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(GetManagedDatabasesDatabaseParametersArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private GetManagedDatabasesDatabaseParametersArgs $;

        public Builder() {
            $ = new GetManagedDatabasesDatabaseParametersArgs();
        }

        public Builder(GetManagedDatabasesDatabaseParametersArgs defaults) {
            $ = new GetManagedDatabasesDatabaseParametersArgs(Objects.requireNonNull(defaults));
        }

        public Builder filters(@Nullable Output<List<GetManagedDatabasesDatabaseParametersFilterArgs>> filters) {
            $.filters = filters;
            return this;
        }

        public Builder filters(List<GetManagedDatabasesDatabaseParametersFilterArgs> filters) {
            return filters(Output.of(filters));
        }

        public Builder filters(GetManagedDatabasesDatabaseParametersFilterArgs... filters) {
            return filters(List.of(filters));
        }

        /**
         * @param isAllowedValuesIncluded When true, results include a list of valid values for parameters (if applicable).
         * 
         * @return builder
         * 
         */
        public Builder isAllowedValuesIncluded(@Nullable Output<Boolean> isAllowedValuesIncluded) {
            $.isAllowedValuesIncluded = isAllowedValuesIncluded;
            return this;
        }

        /**
         * @param isAllowedValuesIncluded When true, results include a list of valid values for parameters (if applicable).
         * 
         * @return builder
         * 
         */
        public Builder isAllowedValuesIncluded(Boolean isAllowedValuesIncluded) {
            return isAllowedValuesIncluded(Output.of(isAllowedValuesIncluded));
        }

        /**
         * @param managedDatabaseId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
         * 
         * @return builder
         * 
         */
        public Builder managedDatabaseId(Output<String> managedDatabaseId) {
            $.managedDatabaseId = managedDatabaseId;
            return this;
        }

        /**
         * @param managedDatabaseId The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
         * 
         * @return builder
         * 
         */
        public Builder managedDatabaseId(String managedDatabaseId) {
            return managedDatabaseId(Output.of(managedDatabaseId));
        }

        /**
         * @param name A filter to return all parameters that have the text given in their names.
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name A filter to return all parameters that have the text given in their names.
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param opcNamedCredentialId The OCID of the Named Credential.
         * 
         * @return builder
         * 
         */
        public Builder opcNamedCredentialId(@Nullable Output<String> opcNamedCredentialId) {
            $.opcNamedCredentialId = opcNamedCredentialId;
            return this;
        }

        /**
         * @param opcNamedCredentialId The OCID of the Named Credential.
         * 
         * @return builder
         * 
         */
        public Builder opcNamedCredentialId(String opcNamedCredentialId) {
            return opcNamedCredentialId(Output.of(opcNamedCredentialId));
        }

        /**
         * @param source The source used to list database parameters. `CURRENT` is used to get the database parameters that are currently in effect for the database instance. `SPFILE` is used to list parameters from the server parameter file. Default is `CURRENT`.
         * 
         * @return builder
         * 
         */
        public Builder source(@Nullable Output<String> source) {
            $.source = source;
            return this;
        }

        /**
         * @param source The source used to list database parameters. `CURRENT` is used to get the database parameters that are currently in effect for the database instance. `SPFILE` is used to list parameters from the server parameter file. Default is `CURRENT`.
         * 
         * @return builder
         * 
         */
        public Builder source(String source) {
            return source(Output.of(source));
        }

        public GetManagedDatabasesDatabaseParametersArgs build() {
            if ($.managedDatabaseId == null) {
                throw new MissingRequiredPropertyException("GetManagedDatabasesDatabaseParametersArgs", "managedDatabaseId");
            }
            return $;
        }
    }

}
