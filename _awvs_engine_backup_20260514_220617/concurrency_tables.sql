--
-- PostgreSQL database dump
--

\restrict hEbutrBwpBWnOEs1QFN9xnpXed0RWBqM5QkPT4dABXLSJwE8wmEgfFjggZ9PsNo

-- Dumped from database version 17.6
-- Dumped by pg_dump version 17.6

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: config_overrides; Type: TABLE; Schema: public; Owner: wvs
--

CREATE TABLE public.config_overrides (
    config_id uuid NOT NULL,
    owner_id uuid NOT NULL,
    creator_id uuid NOT NULL,
    target_id uuid,
    group_id uuid,
    created timestamp with time zone NOT NULL,
    name text NOT NULL,
    type character varying NOT NULL,
    data jsonb NOT NULL
);


ALTER TABLE public.config_overrides OWNER TO wvs;

--
-- Name: system_config; Type: TABLE; Schema: public; Owner: wvs
--

CREATE TABLE public.system_config (
    name text NOT NULL,
    value jsonb
);


ALTER TABLE public.system_config OWNER TO wvs;

--
-- Name: system_config_mu; Type: TABLE; Schema: public; Owner: wvs
--

CREATE TABLE public.system_config_mu (
    user_id uuid NOT NULL,
    name text NOT NULL,
    value jsonb
);


ALTER TABLE public.system_config_mu OWNER TO wvs;

--
-- Name: workers; Type: TABLE; Schema: public; Owner: wvs
--

CREATE TABLE public.workers (
    worker_id text NOT NULL,
    scanning_app text NOT NULL,
    endpoint text,
    max_job_count integer,
    created timestamp with time zone,
    start_date timestamp with time zone,
    shutdown_date timestamp with time zone,
    api_key text,
    ssl_verify boolean DEFAULT false,
    status text,
    worker_type text DEFAULT 'fixed'::text,
    description text,
    "authorization" text,
    info jsonb
);


ALTER TABLE public.workers OWNER TO wvs;

--
-- Data for Name: config_overrides; Type: TABLE DATA; Schema: public; Owner: wvs
--

COPY public.config_overrides (config_id, owner_id, creator_id, target_id, group_id, created, name, type, data) FROM stdin;
\.


--
-- Data for Name: system_config; Type: TABLE DATA; Schema: public; Owner: wvs
--

COPY public.system_config (name, value) FROM stdin;
app_ini_hash	"adb6a73ed30d0ea7fa0159204bb1a7850eceb43207e376a019986c0bb35abbbb"
22e0eae9b4e4e180648a62a3bc0da5c7	"47467b2c97078cfea2b5b31ff7869a09"
proxy	{"port": 7890, "address": "127.0.0.1", "enabled": true, "protocol": "http"}
\.


--
-- Data for Name: system_config_mu; Type: TABLE DATA; Schema: public; Owner: wvs
--

COPY public.system_config_mu (user_id, name, value) FROM stdin;
\.


--
-- Data for Name: workers; Type: TABLE DATA; Schema: public; Owner: wvs
--

COPY public.workers (worker_id, scanning_app, endpoint, max_job_count, created, start_date, shutdown_date, api_key, ssl_verify, status, worker_type, description, "authorization", info) FROM stdin;
\.


--
-- Name: config_overrides conf_overrides_pkey; Type: CONSTRAINT; Schema: public; Owner: wvs
--

ALTER TABLE ONLY public.config_overrides
    ADD CONSTRAINT conf_overrides_pkey PRIMARY KEY (config_id);


--
-- Name: system_config_mu system_config_mu_pkey; Type: CONSTRAINT; Schema: public; Owner: wvs
--

ALTER TABLE ONLY public.system_config_mu
    ADD CONSTRAINT system_config_mu_pkey PRIMARY KEY (user_id, name);


--
-- Name: system_config system_config_pkey; Type: CONSTRAINT; Schema: public; Owner: wvs
--

ALTER TABLE ONLY public.system_config
    ADD CONSTRAINT system_config_pkey PRIMARY KEY (name);


--
-- Name: workers workers_pkey; Type: CONSTRAINT; Schema: public; Owner: wvs
--

ALTER TABLE ONLY public.workers
    ADD CONSTRAINT workers_pkey PRIMARY KEY (worker_id);


--
-- Name: ix_workers_scanning_app; Type: INDEX; Schema: public; Owner: wvs
--

CREATE INDEX ix_workers_scanning_app ON public.workers USING btree (scanning_app);


--
-- Name: ix_workers_status; Type: INDEX; Schema: public; Owner: wvs
--

CREATE INDEX ix_workers_status ON public.workers USING btree (status);


--
-- Name: config_overrides conf_overrides_user_id_fk; Type: FK CONSTRAINT; Schema: public; Owner: wvs
--

ALTER TABLE ONLY public.config_overrides
    ADD CONSTRAINT conf_overrides_user_id_fk FOREIGN KEY (owner_id) REFERENCES public.users(user_id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: config_overrides conf_overrides_user_id_fk2; Type: FK CONSTRAINT; Schema: public; Owner: wvs
--

ALTER TABLE ONLY public.config_overrides
    ADD CONSTRAINT conf_overrides_user_id_fk2 FOREIGN KEY (creator_id) REFERENCES public.users(user_id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: system_config_mu system_config_mu_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: wvs
--

ALTER TABLE ONLY public.system_config_mu
    ADD CONSTRAINT system_config_mu_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict hEbutrBwpBWnOEs1QFN9xnpXed0RWBqM5QkPT4dABXLSJwE8wmEgfFjggZ9PsNo

