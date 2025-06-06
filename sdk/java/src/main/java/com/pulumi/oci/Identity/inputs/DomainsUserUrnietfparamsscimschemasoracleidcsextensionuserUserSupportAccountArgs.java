// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserSupportAccountArgs extends com.pulumi.resources.ResourceArgs {

    public static final DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserSupportAccountArgs Empty = new DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserSupportAccountArgs();

    /**
     * (Updatable) The OCID of the user&#39;s support account.
     * 
     * **Added In:** 2103141444
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: always
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="ocid")
    private @Nullable Output<String> ocid;

    /**
     * @return (Updatable) The OCID of the user&#39;s support account.
     * 
     * **Added In:** 2103141444
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: always
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> ocid() {
        return Optional.ofNullable(this.ocid);
    }

    /**
     * (Updatable) The URI of the corresponding Support Account resource to which the user belongs
     * 
     * **Added In:** 2103141444
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: reference
     * * uniqueness: none
     * 
     */
    @Import(name="ref")
    private @Nullable Output<String> ref;

    /**
     * @return (Updatable) The URI of the corresponding Support Account resource to which the user belongs
     * 
     * **Added In:** 2103141444
     * 
     * **SCIM++ Properties:**
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: default
     * * type: reference
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> ref() {
        return Optional.ofNullable(this.ref);
    }

    /**
     * (Updatable) User Support User Id
     * 
     * **Added In:** 2103141444
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: always
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="userId")
    private @Nullable Output<String> userId;

    /**
     * @return (Updatable) User Support User Id
     * 
     * **Added In:** 2103141444
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: always
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> userId() {
        return Optional.ofNullable(this.userId);
    }

    /**
     * (Updatable) User Support Account Provider
     * 
     * **Added In:** 2103141444
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: always
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="userProvider")
    private @Nullable Output<String> userProvider;

    /**
     * @return (Updatable) User Support Account Provider
     * 
     * **Added In:** 2103141444
     * 
     * **SCIM++ Properties:**
     * * caseExact: false
     * * idcsSearchable: false
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: always
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> userProvider() {
        return Optional.ofNullable(this.userProvider);
    }

    /**
     * (Updatable) The identifier of the User&#39;s support Account.
     * 
     * **Added In:** 2103141444
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: always
     * * type: string
     * * uniqueness: none
     * 
     */
    @Import(name="value")
    private @Nullable Output<String> value;

    /**
     * @return (Updatable) The identifier of the User&#39;s support Account.
     * 
     * **Added In:** 2103141444
     * 
     * **SCIM++ Properties:**
     * * caseExact: true
     * * idcsSearchable: true
     * * multiValued: false
     * * mutability: readOnly
     * * required: false
     * * returned: always
     * * type: string
     * * uniqueness: none
     * 
     */
    public Optional<Output<String>> value() {
        return Optional.ofNullable(this.value);
    }

    private DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserSupportAccountArgs() {}

    private DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserSupportAccountArgs(DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserSupportAccountArgs $) {
        this.ocid = $.ocid;
        this.ref = $.ref;
        this.userId = $.userId;
        this.userProvider = $.userProvider;
        this.value = $.value;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserSupportAccountArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserSupportAccountArgs $;

        public Builder() {
            $ = new DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserSupportAccountArgs();
        }

        public Builder(DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserSupportAccountArgs defaults) {
            $ = new DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserSupportAccountArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param ocid (Updatable) The OCID of the user&#39;s support account.
         * 
         * **Added In:** 2103141444
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: always
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder ocid(@Nullable Output<String> ocid) {
            $.ocid = ocid;
            return this;
        }

        /**
         * @param ocid (Updatable) The OCID of the user&#39;s support account.
         * 
         * **Added In:** 2103141444
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: always
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder ocid(String ocid) {
            return ocid(Output.of(ocid));
        }

        /**
         * @param ref (Updatable) The URI of the corresponding Support Account resource to which the user belongs
         * 
         * **Added In:** 2103141444
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: reference
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder ref(@Nullable Output<String> ref) {
            $.ref = ref;
            return this;
        }

        /**
         * @param ref (Updatable) The URI of the corresponding Support Account resource to which the user belongs
         * 
         * **Added In:** 2103141444
         * 
         * **SCIM++ Properties:**
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: default
         * * type: reference
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder ref(String ref) {
            return ref(Output.of(ref));
        }

        /**
         * @param userId (Updatable) User Support User Id
         * 
         * **Added In:** 2103141444
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: always
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder userId(@Nullable Output<String> userId) {
            $.userId = userId;
            return this;
        }

        /**
         * @param userId (Updatable) User Support User Id
         * 
         * **Added In:** 2103141444
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: always
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder userId(String userId) {
            return userId(Output.of(userId));
        }

        /**
         * @param userProvider (Updatable) User Support Account Provider
         * 
         * **Added In:** 2103141444
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: always
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder userProvider(@Nullable Output<String> userProvider) {
            $.userProvider = userProvider;
            return this;
        }

        /**
         * @param userProvider (Updatable) User Support Account Provider
         * 
         * **Added In:** 2103141444
         * 
         * **SCIM++ Properties:**
         * * caseExact: false
         * * idcsSearchable: false
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: always
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder userProvider(String userProvider) {
            return userProvider(Output.of(userProvider));
        }

        /**
         * @param value (Updatable) The identifier of the User&#39;s support Account.
         * 
         * **Added In:** 2103141444
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: always
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder value(@Nullable Output<String> value) {
            $.value = value;
            return this;
        }

        /**
         * @param value (Updatable) The identifier of the User&#39;s support Account.
         * 
         * **Added In:** 2103141444
         * 
         * **SCIM++ Properties:**
         * * caseExact: true
         * * idcsSearchable: true
         * * multiValued: false
         * * mutability: readOnly
         * * required: false
         * * returned: always
         * * type: string
         * * uniqueness: none
         * 
         * @return builder
         * 
         */
        public Builder value(String value) {
            return value(Output.of(value));
        }

        public DomainsUserUrnietfparamsscimschemasoracleidcsextensionuserUserSupportAccountArgs build() {
            return $;
        }
    }

}
